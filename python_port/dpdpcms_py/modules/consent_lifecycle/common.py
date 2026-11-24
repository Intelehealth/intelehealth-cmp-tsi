from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    canonical_purpose_id,
    require,
)
from dpdpcms_py.modules.administration.api import resolve_fiduciary


def _fid(ctx: RequestContext) -> str:
    return require(resolve_fiduciary(ctx), "fiduciary_id")


# Principal identifiers are stored as <col>_enc (pgp ciphertext) and <col>_hmac
# (lookup key). Every match goes through the HMAC; a read decrypts the pair
# back to <col> and hands it through pii.principal_view (masked for operators).
_USER_MATCH = pii.match_sql("user_id")


# SELECT list for a full consent_records row with the identifier, the session
# IP and the claimed IP (client_metadata.ip_address_enc) decrypted; bind
# *_consent_keys() ahead of the WHERE parameters.
_CLAIMED_IP_SQL = pii.dec_sql("client_metadata->>'ip_address_enc'")


_CONSENT_COLUMNS = (
    f"*, {pii.dec_sql('user_id_enc')} AS user_id, {pii.dec_sql('ip_address_enc')} AS ip_address,"
    f" {_CLAIMED_IP_SQL} AS claimed_ip_address"
)


# client_metadata as stored: the caller's claims, with a claimed IP encrypted
# under 'ip_address_enc' (absent when none was claimed); bind
# (db.as_jsonb(claims), *db.bind_encrypt(claimed_ip)).
_CLIENT_METADATA_SQL = (
    "(%s::jsonb || jsonb_strip_nulls(jsonb_build_object('ip_address_enc',"
    " encode(pgp_sym_encrypt(%s::text, %s), 'base64'))))"
)


def _consent_keys() -> tuple[str, ...]:
    return (*db.bind_key(), *db.bind_key(), *db.bind_key())


def _consent_row(ctx: RequestContext, row: dict | None) -> dict | None:
    """A consent record as the caller may see it. The stored ciphertext never
    leaves; the session IP (and any IP the integrator claimed) is shown to
    API-key and principal callers, and is null for console operators - a DPO
    sees it through the logged reveal."""
    if not row:
        return None
    out = pii.principal_row(ctx, row, "user_id")
    out.pop("ip_address_enc", None)
    claimed_ip = out.pop("claimed_ip_address", None)
    operator = ctx.operator_id is not None
    if operator:
        out["ip_address"] = None
    meta = out.get("client_metadata")
    if isinstance(meta, dict) and "ip_address_enc" in meta:
        meta = {key: value for key, value in meta.items() if key != "ip_address_enc"}
        meta["ip_address"] = None if operator else claimed_ip
        out["client_metadata"] = meta
    return out


def _purpose_names(policy_content: Any, language: str) -> dict[str, str]:
    """purpose id (lower-case) -> name, from the policy block for `language`,
    falling back to English and then to whichever block the policy has."""
    if not isinstance(policy_content, dict) or not policy_content:
        return {}
    block = policy_content.get(language) or policy_content.get("en") or next(iter(policy_content.values()))
    if not isinstance(block, dict):
        return {}
    return {
        canonical_purpose_id(p.get("id")): str(p["name"])
        for p in block.get("data_processing_purposes") or []
        if isinstance(p, dict) and p.get("id") and p.get("name")
    }


def _point_granted(point: dict) -> bool:
    """Data points are stored as {data_point_id, consent_granted, consent_expiry}; an expired
    grant no longer counts. 'status' is accepted as an older alias for consent_granted."""
    granted = point.get("consent_granted")
    if granted is None:
        granted = str(point.get("status", "")).lower() in {"granted", "true", "consent_given"}
    if not granted:
        return False
    expiry = point.get("consent_expiry")
    if expiry:
        # P12-01: a stored expiry never makes a read raise. A naive value is read
        # as UTC; one that does not parse is ignored, as before.
        try:
            when = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return True
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        if when <= datetime.now(UTC):
            return False
    return True


def observed_mechanism(ctx: RequestContext) -> str:
    """CC-04/CC-06: how the consent reached the CMS, as the server saw it, never as the caller claims."""
    if ctx.auth_via_principal_jwt:
        return "PRINCIPAL_PORTAL"
    if ctx.category == "admin":
        return "ADMIN_CONSOLE"
    return "INTEGRATOR_API"


def _observed_metadata(ctx: RequestContext) -> dict[str, Any]:
    """Server-observed capture metadata, plus whatever the caller claimed, kept apart."""
    payload = ctx.payload
    session_id = ctx.session_id or payload.get("session_id")
    return {
        "mechanism": observed_mechanism(ctx),
        "ip_address": ctx.source_ip or "0.0.0.0",
        "user_agent": ctx.headers.get("user-agent") or ctx.headers.get("User-Agent"),
        "session_id": session_id,
        # A principal session id comes from the CMS's own token; an integrator's is its claim.
        "session_source": "CMS" if ctx.session_id else ("CLIENT" if session_id else None),
        # The claimed IP is stored encrypted apart from the other claims (_CLIENT_METADATA_SQL).
        "client_metadata": {
            key: payload[key]
            for key in ("consent_mechanism", "user_agent", "session_id")
            if payload.get(key) is not None
        },
        "claimed_ip_address": None if payload.get("ip_address") is None else str(payload["ip_address"]),
    }


def _raise_consent_alert(fiduciary_id: str, alert_type: str, record_id: str | None, payload: dict) -> None:
    """NT-07: an alert row (acknowledgeable, escalated by the worker) plus its dispatch."""
    try:
        from dpdpcms_py.modules.notifications.api import enqueue_alert_dispatch, record_alert

        enqueue_alert_dispatch(fiduciary_id, record_alert(fiduciary_id, alert_type, record_id, payload))
    except Exception:  # pragma: no cover - an alert failure never undoes the consent action
        pass


def _require_console_operator(ctx: RequestContext) -> None:
    """Console-only reads: an API key or principal token never reaches them.

    Over HTTP the client category already refuses these functions (they are not
    in CLIENT_ALLOWED_FUNCS) and the admin category refuses a principal token;
    this is the same refusal for a direct call, as PiiService makes."""
    if not ctx.operator_id or ctx.auth_via_principal_jwt:
        raise ApiError(403, "Forbidden", "Only a console operator may read this.")


def _console_record(ctx: RequestContext, columns: str, keys: tuple = ()) -> dict:
    """The consent record a console read names (consent_record_id), in the caller's tenant, or 400/404.

    `keys` are the bound parameters of `columns` (db.bind_key() per decrypted column)."""
    fid = _fid(ctx)
    record_id = str(require(ctx.payload.get("consent_record_id"), "consent_record_id"))
    for value, name in ((record_id, "consent_record_id"), (fid, "fiduciary_id")):
        try:
            uuid.UUID(value)
        except ValueError:
            raise ApiError(400, "Bad Request", f"Invalid '{name}'.") from None
    row = db.one(f"SELECT {columns} FROM consent_records WHERE id = %s AND fiduciary_id = %s", (*keys, record_id, fid))
    if not row:
        raise ApiError(404, "Not Found", "Consent record not found.")
    return row


def _notify_principal(user_id: str, fiduciary_id: str, notification_type: str) -> None:
    db.execute(
        "INSERT INTO notifications (recipient_type, recipient_id_enc, recipient_id_hmac, fiduciary_id, notification_type)"
        f" VALUES ('PRINCIPAL', {pii.ENC_SQL}, {pii.HMAC_SQL}, %s, %s)",
        (*pii.pid_params(user_id), fiduciary_id, notification_type),
    )
