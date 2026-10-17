from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from .. import db, pii, principal_otp
from ..audit import log_event
from ..context import RequestContext
from ..errors import ApiError
from ..security import principal_token
from .base import (
    Service,
    bind_principal_field,
    canonical_consent_points,
    canonical_purpose_id,
    csv_safe,
    ensure_principal_owns,
    page_limit,
    point_purpose_id,
    reject_principal,
    require,
)
from .catalog import resolve_fiduciary, served_policy_version


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


NOTIF_CONSENT_GIVEN = "CONSENT_GIVEN_NOTIFICATION"
NOTIF_WITHDRAWAL_ACK = "WITHDRAWAL_ACKNOWLEDGMENT"
NOTIF_ERASURE_REQUESTED = "ERASURE_REQUESTED_NOTIFICATION"
NOTIF_VALIDATION_DENIED = "CONSENT_VALIDATION_DENIED"

# CC-05: how a guardian's identity may be established. Only EXISTING_ACCOUNT and
# DIGILOCKER can reach VERIFIED; the rest are recorded as assertions.
GUARDIAN_MECHANISMS = {"EXISTING_ACCOUNT", "DIGILOCKER", "AADHAAR_VC", "KYC_PROVIDER", "OTP_LINKING"}

# Cessation-based retention window stamped on each purpose at withdrawal (Section
# 8(7)). Mirrors the Java build, which recorded a 1095-day expiry per purpose.
RETENTION_CESSATION_DAYS = 1095


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


def _point_grants(point: dict, purpose_id: str) -> bool:
    """As above, for one specific purpose. 'id'/'purpose_id' are older aliases for data_point_id."""
    stored_id = point_purpose_id(point)
    if not stored_id or stored_id != canonical_purpose_id(purpose_id):
        return False
    return _point_granted(point)


def _normalise_purpose_ids(payload: dict) -> list[str]:
    """Collect the purpose selection from 'purpose_ids' (array/string) and the legacy 'purpose_id' alias."""
    raw = payload.get("purpose_ids") or []
    if isinstance(raw, str):
        raw = [raw]
    ids = [canonical_purpose_id(item) for item in raw if item is not None and str(item).strip()]
    single = payload.get("purpose_id")
    if single is not None and str(single).strip() and canonical_purpose_id(single) not in ids:
        ids.append(canonical_purpose_id(single))
    return ids


def declared_purpose_ids(policy_content: dict | None) -> set[str]:
    """Purpose IDs declared across every language block of a policy."""
    if not isinstance(policy_content, dict):
        return set()
    ids: set[str] = set()
    for block in policy_content.values():
        if not isinstance(block, dict):
            continue
        for purpose in block.get("data_processing_purposes") or []:
            if isinstance(purpose, dict) and purpose.get("id"):
                ids.add(canonical_purpose_id(purpose["id"]))
    return ids


def check_consent_alignment(fiduciary_id: str, policy_id: str, version: str, data_consents: list[Any]) -> set[str]:
    """CU-05: every purpose in a consent submission must be declared by the policy,
    and no CLOSED purpose (PL-02/03) may be granted. Returns the closed purpose ids
    (lower-case) so the explicit-choice check does not demand a decision on them."""
    policy = db.one(
        "SELECT policy_content, status, effective_date <= NOW() AS in_effect FROM consent_policies WHERE id = %s AND version = %s AND fiduciary_id = %s",
        (policy_id, version, fiduciary_id),
    )
    if not policy:
        raise ApiError(404, "Not Found", f"Policy {policy_id} version {version} not found.")
    # P9-02: consent may only rest on a notice the principal could have been
    # shown, i.e. the version get_active_policy serves: ACTIVE and in effect.
    # A DRAFT was never published and an ARCHIVED version is no longer served.
    # P11-03: several versions can be ACTIVE and in effect until the superseded
    # one is archived; only the newest - the one served - may take consent.
    if (
        str(policy.get("status") or "").upper() != "ACTIVE"
        or policy.get("in_effect") is False
        or served_policy_version(policy_id, fiduciary_id) != str(version)
    ):
        raise ApiError(
            409,
            "Conflict",
            f"Policy {policy_id} version {version} is not the active, in-effect notice; consent cannot be recorded against it.",
        )
    declared = declared_purpose_ids(policy.get("policy_content"))

    requested: set[str] = set()
    granted: set[str] = set()
    if isinstance(data_consents, list):
        for point in data_consents:
            if not isinstance(point, dict):
                continue
            pid = point_purpose_id(point)
            if pid:
                requested.add(pid)
                if point.get("consent_granted") is True:
                    granted.add(pid)
    for pid in requested:
        if pid not in declared:
            raise ApiError(
                400,
                "Bad Request",
                f"Purpose '{pid}' is not declared in policy {policy_id} version {version}.",
            )

    closed = db.all(
        "SELECT purpose_id FROM purpose_lifecycle WHERE fiduciary_id = %s AND state = 'CLOSED'",
        (fiduciary_id,),
    )
    closed_ids = {canonical_purpose_id(row["purpose_id"]) for row in closed}
    # PL-02: a closed purpose may still be declared by the policy until a new
    # version drops it. Declining it (or leaving it out) is fine; granting it is not.
    overlap = granted & closed_ids
    if overlap:
        raise ApiError(
            403,
            "Forbidden",
            f"Purpose(s) {sorted(overlap)} are closed — consent cannot be granted for a closed purpose.",
        )
    return closed_ids


def check_explicit_choices(policy_content: dict | None, data_consents: Any, closed: set[str] | None = None) -> None:
    """CC-03: consent must be granular and affirmative, never bundled or implied.

    Every purpose the policy declares needs its own explicit yes/no in the
    submission (an omitted purpose would otherwise read as a silent default),
    each decision must be a real boolean, and no purpose may appear twice.
    A CLOSED purpose (PL-02) needs no decision: it can no longer be granted.
    """
    if not isinstance(data_consents, list) or not data_consents:
        raise ApiError(400, "Bad Request", "data_point_consents must list a decision for each purpose.")
    seen: set[str] = set()
    for point in data_consents:
        if not isinstance(point, dict):
            raise ApiError(400, "Bad Request", "data_point_consents entries must be objects.")
        pid = point_purpose_id(point)
        if not pid:
            raise ApiError(400, "Bad Request", "Each consent decision must name its data_point_id.")
        if pid in seen:
            raise ApiError(400, "Bad Request", f"Purpose '{pid}' appears more than once.")
        seen.add(pid)
        if not isinstance(point.get("consent_granted"), bool):
            raise ApiError(
                400,
                "Bad Request",
                f"Purpose '{pid}' needs an explicit consent_granted true/false; consent is never implied (CC-03).",
            )
    exempt = seen | (closed or set())
    undecided = sorted(d for d in declared_purpose_ids(policy_content) if d not in exempt)
    if undecided:
        raise ApiError(
            400,
            "Bad Request",
            f"No explicit decision for purpose(s) {undecided}; every purpose must be accepted or declined individually.",
        )


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


def _verify_with_digilocker(fiduciary_id: str, guardian_id: str, ref_id: str) -> tuple[str, str | None]:
    """Confirm a DigiLocker reference through the configured verifier service.

    The verifier is the deployment's DigiLocker partner integration. It receives
    the reference and answers {"verified": bool, "is_adult": bool}. With no
    verifier configured the log stays PENDING and cannot back a minor's consent.
    """
    from ..config import settings
    from ..netutil import post_json

    if not settings.digilocker_verify_url:
        return "PENDING", "No DigiLocker verifier is configured (DIGILOCKER_VERIFY_URL)."
    try:
        status, body = post_json(
            settings.digilocker_verify_url,
            {"fiduciary_id": fiduciary_id, "guardian_principal_id": guardian_id, "verification_ref_id": ref_id},
            timeout=15,
        )
    except ValueError as exc:
        return "PENDING", str(exc)
    if status is None or status >= 400:
        return "PENDING", f"DigiLocker verifier unavailable ({status})."
    try:
        answer = json.loads(body or "{}")
    except ValueError:
        return "PENDING", "DigiLocker verifier returned an unreadable response."
    if answer.get("verified") is True and answer.get("is_adult") is True:
        return "VERIFIED", None
    return "REJECTED", "DigiLocker did not confirm an adult guardian for this reference."


def _raise_consent_alert(fiduciary_id: str, alert_type: str, record_id: str | None, payload: dict) -> None:
    """NT-07: an alert row (acknowledgeable, escalated by the worker) plus its dispatch."""
    try:
        from .alerts import enqueue_alert_dispatch
        from .lifecycle import record_alert

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


def _has_proof_metadata(proof: str | None) -> bool:
    """Whether the guardian log holds caller-supplied proof, beyond the server's own verification_detail."""
    if not proof:
        return False
    try:
        value = json.loads(proof)
    except ValueError:
        return True
    if isinstance(value, dict):
        return any(v not in (None, "", {}, []) for k, v in value.items() if k != "verification_detail")
    return value not in (None, "", {}, [])


def _verification_detail(proof: str | None) -> str | None:
    """The server-written verification_detail record_parent_consent stores beside the proof."""
    try:
        value = json.loads(proof) if proof else None
    except ValueError:
        return None
    return value.get("verification_detail") if isinstance(value, dict) else None


TRAIL_ALL = "ALL"


def _policy_block(policy_content: Any, language: str) -> dict:
    """The policy's block for `language`, else English, else its first block."""
    if not isinstance(policy_content, dict) or not policy_content:
        return {}
    block = policy_content.get(language) or policy_content.get("en") or next(iter(policy_content.values()))
    return block if isinstance(block, dict) else {}


def _purpose_fields(block: dict) -> dict[str, list[str]]:
    """purpose id -> the names of the data categories it covers, from the policy block.

    Names come from data_categories_details (falling back to the category id);
    they are category labels, never personal data. 'ALL' covers every category
    any purpose names, in declaration order."""
    names = {
        str(c["id"]): str(c.get("name") or c["id"])
        for c in block.get("data_categories_details") or []
        if isinstance(c, dict) and c.get("id")
    }
    out: dict[str, list[str]] = {}
    every: list[str] = []
    for purpose in block.get("data_processing_purposes") or []:
        if not isinstance(purpose, dict) or not purpose.get("id"):
            continue
        fields: list[str] = []
        for category in purpose.get("data_categories_involved") or []:
            name = names.get(str(category), str(category))
            if name not in fields:
                fields.append(name)
            if name not in every:
                every.append(name)
        out[canonical_purpose_id(purpose["id"])] = fields
    out[TRAIL_ALL] = every
    return out


# Context keys by which an audit row names the consent record it is about:
# record_id (CONSENT_GIVEN / CONSENT_WITHDRAWN / ERASURE_REQUESTED) and
# consent_record_id (processor and integrator events).
TRAIL_RECORD_KEYS = ("record_id", "consent_record_id")


def _trail_context(raw: Any) -> Any:
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def _notify_principal(user_id: str, fiduciary_id: str, notification_type: str) -> None:
    db.execute(
        "INSERT INTO notifications (recipient_type, recipient_id_enc, recipient_id_hmac, fiduciary_id, notification_type)"
        f" VALUES ('PRINCIPAL', {pii.ENC_SQL}, {pii.HMAC_SQL}, %s, %s)",
        (*pii.pid_params(user_id), fiduciary_id, notification_type),
    )


class ConsentService(Service):
    def record_consent(self, ctx: RequestContext) -> dict:
        payload = ctx.payload
        bind_principal_field(ctx, "user_id")
        fid = _fid(ctx)
        user_id = require(payload.get("user_id"), "user_id")
        policy_id = require(payload.get("policy_id"), "policy_id")
        # PT-02: the language is a code from the closed list, never free text
        # (it is echoed into the principal's CSV and PDF exports).
        from ..defaults import NOTIFICATION_LANGUAGES

        language = str(payload.get("language_selected") or "en").strip().lower()
        if language not in NOTIFICATION_LANGUAGES:
            raise ApiError(400, "Bad Request", "language_selected must be en or an Eighth Schedule language code.")
        payload["language_selected"] = language
        # P10-01: one purpose per decision, stored under data_point_id only.
        data_consents = canonical_consent_points(require(payload.get("data_point_consents"), "data_point_consents"))
        payload["data_point_consents"] = data_consents
        requested_version = payload.get("version") or payload.get("policy_version") or ""
        if requested_version:
            policy = db.one(
                "SELECT version, policy_content FROM consent_policies WHERE id = %s AND version = %s AND fiduciary_id = %s",
                (policy_id, requested_version, fid),
            )
            if not policy:
                raise ApiError(
                    400, "Bad Request", f"Policy version mismatch: no version '{requested_version}' for {policy_id}."
                )
            version = requested_version
        else:
            # Notice versioning: when the client does not state which notice the
            # principal agreed to, stamp the current (preferring ACTIVE) version so
            # the consent record always identifies the notice it points at.
            # P11-03: that is the served version when there is one.
            served = served_policy_version(policy_id, fid)
            policy = db.one(
                "SELECT version, policy_content FROM consent_policies WHERE id = %s AND fiduciary_id = %s ORDER BY (version = %s) DESC, (status = 'ACTIVE') DESC, effective_date DESC LIMIT 1",
                (policy_id, fid, served or ""),
            )
            if not policy:
                raise ApiError(400, "Bad Request", f"Policy not found: {policy_id}.")
            version = policy["version"]
        # CU-05: the submission may only reference purposes the policy declares,
        # and never grant a purpose that is CLOSED under the purpose lifecycle.
        closed = check_consent_alignment(fid, policy_id, version, data_consents)
        check_explicit_choices(policy.get("policy_content"), data_consents, closed)
        # SEC-05: age_category is never silently defaulted to ADULT. When the
        # payload names one it is honoured (MINOR still requires a VERIFIED
        # guardian log below); when it is silent the existing value survives via
        # COALESCE. An upsert default overwriting a MINOR row closes the s.9 gate.
        age_category = str(payload["age_category"]).upper() if payload.get("age_category") else None
        guardian_id = payload.get("guardian_id")
        verification_log_id = payload.get("verification_log_id")
        # SEC-05 (residual): the s.9 gate keys off the STORED record, not the
        # body. A principal the CMS already classified as MINOR stays a minor
        # when the request omits age_category (the old code skipped the gate)
        # and cannot be flipped to ADULT over the wire, since nothing downstream
        # compares the two values.
        stored = db.one(
            f"SELECT age_category FROM data_principal WHERE {_USER_MATCH} AND fiduciary_id = %s",
            (*pii.hmac_params(user_id), fid),
        )
        stored_age = str(stored["age_category"]).strip().upper() if stored and stored.get("age_category") else None
        if stored_age == "MINOR" and age_category == "ADULT":
            raise ApiError(
                403,
                "Forbidden",
                "This principal is recorded as a minor; consent can only be recorded with a verified guardian.",
            )
        effective_age = "MINOR" if stored_age == "MINOR" else age_category
        if effective_age == "MINOR":
            # CC-05: a minor's consent always rests on a VERIFIED guardian log;
            # naming a guardian_id alone is an assertion, not a verification.
            where = (
                f"child_principal_id_hmac = {pii.HMAC_SQL} AND fiduciary_id = %s AND verification_status = 'VERIFIED'"
            )
            params: list[Any] = [*db.bind_key(), *pii.hmac_params(user_id), fid]
            if guardian_id:
                where += f" AND guardian_principal_id_hmac = {pii.HMAC_SQL}"
                params.extend(pii.hmac_params(guardian_id))
            if verification_log_id:
                where += " AND id = %s"
                params.append(verification_log_id)
            parent_log = db.one(
                f"SELECT id, {pii.dec_sql('guardian_principal_id_enc')} AS guardian_principal_id"
                f" FROM parental_verification_logs WHERE {where} ORDER BY verified_at DESC LIMIT 1",
                params,
            )
            if not parent_log:
                raise ApiError(
                    403, "Forbidden", "A verified guardian consent is required to record consent for a minor."
                )
            verification_log_id = str(parent_log["id"])
            guardian_id = guardian_id or parent_log["guardian_principal_id"]
        observed = _observed_metadata(ctx)
        with db.connection() as conn, conn.cursor() as cur:
            cur.execute(
                # CW-03/UD-05: a principal holds one active record per policy. Recording
                # consent under one policy must not retire their consent under another.
                "UPDATE consent_records SET is_active_consent = FALSE, last_updated_at = NOW()"
                f" WHERE {_USER_MATCH} AND fiduciary_id = %s AND policy_id = %s AND is_active_consent IS TRUE RETURNING id",
                (*pii.hmac_params(user_id), fid, policy_id),
            )
            prior = cur.fetchone()
            cur.execute(
                f"""
                INSERT INTO consent_records
                    (id, user_id_enc, user_id_hmac, fiduciary_id, policy_id, policy_version, timestamp,
                     jurisdiction, language_selected, consent_status_general, consent_mechanism,
                     ip_address_enc, user_agent, data_point_consents, is_active_consent,
                     verification_log_id, session_id, session_source, client_metadata,
                     supersedes_record_id, created_at, last_updated_at)
                VALUES (uuid_generate_v4(), {pii.ENC_SQL}, {pii.HMAC_SQL}, %s, %s, %s, NOW(), %s, %s, %s, %s,
                        {db.enc_expr()}, %s, %s, TRUE, %s, %s, %s, {_CLIENT_METADATA_SQL}, %s, NOW(), NOW())
                RETURNING id
                """,
                (
                    *pii.enc_params(user_id),
                    *pii.hmac_params(user_id),
                    fid,
                    policy_id,
                    version,
                    payload.get("jurisdiction", "IN"),
                    payload.get("language_selected", "en"),
                    "CONSENT_GIVEN",
                    observed["mechanism"],
                    *db.bind_encrypt(observed["ip_address"]),
                    observed["user_agent"],
                    db.as_jsonb(data_consents),
                    verification_log_id,
                    observed["session_id"],
                    observed["session_source"],
                    db.as_jsonb(observed["client_metadata"]),
                    *db.bind_encrypt(observed["claimed_ip_address"]),
                    prior["id"] if prior else None,
                ),
            )
            cid = str(cur.fetchone()["id"])
            cur.execute(
                f"""
                INSERT INTO data_principal
                    (user_id_enc, user_id_hmac, fiduciary_id, last_consent_mechanism, age_category,
                     guardian_id_enc, guardian_id_hmac, verification_status)
                VALUES ({pii.ENC_SQL}, {pii.HMAC_SQL}, %s, %s, %s, {pii.ENC_SQL}, {pii.HMAC_SQL}, %s)
                ON CONFLICT (user_id_hmac, fiduciary_id) DO UPDATE SET
                    last_consent_mechanism = EXCLUDED.last_consent_mechanism,
                    age_category = COALESCE(EXCLUDED.age_category, data_principal.age_category),
                    guardian_id_enc = COALESCE(EXCLUDED.guardian_id_enc, data_principal.guardian_id_enc),
                    guardian_id_hmac = COALESCE(EXCLUDED.guardian_id_hmac, data_principal.guardian_id_hmac),
                    verification_status = COALESCE(EXCLUDED.verification_status, data_principal.verification_status)
                """,
                (
                    *pii.enc_params(user_id),
                    *pii.hmac_params(user_id),
                    fid,
                    observed["mechanism"],
                    effective_age,
                    *pii.enc_params(guardian_id),
                    *pii.hmac_params(guardian_id),
                    "GUARDIAN_VERIFIED" if effective_age == "MINOR" else None,
                ),
            )
        _notify_principal(user_id, fid, NOTIF_CONSENT_GIVEN)
        grant_purpose_ids = []
        declined_purpose_ids = []
        if isinstance(data_consents, list):
            for point in data_consents:
                pid = point_purpose_id(point)
                if not pid:
                    continue
                if _point_granted(point):
                    grant_purpose_ids.append(pid)
                else:
                    declined_purpose_ids.append(pid)
        # CU-09: the audit row names every purpose the grant or update decided,
        # not only a single-purpose grant's purpose_id column.
        log_event(
            user_id,
            fid,
            "APP",
            None,
            "CONSENT_GIVEN",
            {
                "policy_id": policy_id,
                "policy_version": version,
                "record_id": cid,
                "supersedes_record_id": str(prior["id"]) if prior else None,
                "purpose_ids": grant_purpose_ids + declined_purpose_ids,
                "granted_purpose_ids": grant_purpose_ids,
                "declined_purpose_ids": declined_purpose_ids,
            },
            purpose_id=grant_purpose_ids[0] if len(grant_purpose_ids) == 1 else None,
            consent_status="CONSENT_GIVEN",
            initiator="PRINCIPAL" if ctx.auth_via_principal_jwt else "INTEGRATOR",
            source_ip=ctx.source_ip,
        )
        try:
            from ..webhooks import queue_webhook

            queue_webhook(
                fid,
                "CONSENT_RECORDED",
                {"user_id": user_id, "policy_id": policy_id, "version": version, "consent_record_id": cid},
            )
        except Exception:  # pragma: no cover
            pass
        # NT-07: new and updated consents raise an acknowledgeable alert.
        _raise_consent_alert(
            fid,
            "CONSENT_UPDATED" if prior else "CONSENT_GIVEN",
            cid,
            {"user_id": user_id, "policy_id": policy_id, "version": version, "granted_purposes": grant_purpose_ids},
        )
        return {"success": True, "data": {"consent_record_id": cid, "message": "Consent recorded successfully."}}

    def record_parent_consent(self, ctx: RequestContext) -> dict:
        """CC-05: record a guardian verification, verifying it where the CMS can.

        EXISTING_ACCOUNT is verified here: the guardian must already be a known
        ADULT principal of this fiduciary. DIGILOCKER is verified by the
        configured verifier (DIGILOCKER_VERIFY_URL), which must confirm the
        reference and that the guardian is an adult. Anything else is stored as
        an unverified assertion and cannot back a minor's consent.
        """
        payload = ctx.payload
        bind_principal_field(ctx, "guardian_principal_id")
        fid = _fid(ctx)
        child = require(payload.get("child_principal_id"), "child_principal_id")
        guardian = require(payload.get("guardian_principal_id"), "guardian_principal_id")
        mechanism = str(require(payload.get("verification_mechanism"), "verification_mechanism")).upper()
        if mechanism not in GUARDIAN_MECHANISMS:
            raise ApiError(400, "Bad Request", f"verification_mechanism must be one of {sorted(GUARDIAN_MECHANISMS)}.")
        if pii.normalize(str(guardian)) == pii.normalize(str(child)):
            raise ApiError(400, "Bad Request", "A principal cannot act as their own guardian.")
        ref_id = payload.get("verification_ref_id")
        status, detail = "ASSERTED", "Recorded as an assertion; only EXISTING_ACCOUNT or DIGILOCKER can verify."
        if mechanism == "EXISTING_ACCOUNT":
            # SEC-05: guardianship is proven by a row the server recorded as
            # ADULT, never by the column default. A principal whose age the CMS
            # has not attested (NULL) cannot vouch for a minor.
            adult = db.one(
                f"SELECT 1 FROM data_principal WHERE {_USER_MATCH} AND fiduciary_id = %s AND age_category = 'ADULT'",
                (*pii.hmac_params(guardian), fid),
            )
            status = "VERIFIED" if adult else "REJECTED"
            detail = None if adult else "Guardian has no adult account with this fiduciary."
        elif mechanism == "DIGILOCKER":
            require(ref_id, "verification_ref_id")
            status, detail = _verify_with_digilocker(fid, guardian, str(ref_id))
        row = db.insert_returning(
            f"""
            INSERT INTO parental_verification_logs
                (id, child_principal_id_enc, child_principal_id_hmac,
                 guardian_principal_id_enc, guardian_principal_id_hmac, verification_mechanism,
                 provider_name, verification_ref_id_enc, proof_metadata_enc, fiduciary_id, verification_status)
            VALUES (uuid_generate_v4(), {pii.ENC_SQL}, {pii.HMAC_SQL}, {pii.ENC_SQL}, {pii.HMAC_SQL},
                    %s, %s, {db.enc_expr()}, {db.enc_expr()}, %s, %s)
            RETURNING id
            """,
            (
                *pii.enc_params(child),
                *pii.hmac_params(child),
                *pii.enc_params(guardian),
                *pii.hmac_params(guardian),
                mechanism,
                payload.get("provider_name") or ("DigiLocker" if mechanism == "DIGILOCKER" else None),
                # Guardian evidence is stored encrypted (db/35); the proof as its JSON text.
                *db.bind_encrypt(None if ref_id is None else str(ref_id)),
                *db.bind_encrypt(
                    json.dumps({**(payload.get("proof_metadata") or {}), "verification_detail": detail}, default=str)
                ),
                fid,
                status,
            ),
        )
        log_event(
            guardian,
            fid,
            "APP",
            None,
            "GUARDIAN_VERIFICATION_RECORDED",
            {"child_principal_id": child, "mechanism": mechanism, "status": status},
            initiator="PRINCIPAL" if ctx.auth_via_principal_jwt else "INTEGRATOR",
            source_ip=ctx.source_ip,
        )
        return {
            "success": True,
            "verification_log_id": str(row["id"]),
            "verification_status": status,
            "detail": detail,
        }

    def get_parental_verification(self, ctx: RequestContext) -> dict:
        """The guardian verification a minor's consent record rests on, masked.

        Ported from Consent-Manager. guardian_id and verification_ref_id are
        masked; the proof itself never leaves (only whether there is one). The
        values in the clear are reveal_user_id's, under audit."""
        _require_console_operator(ctx)
        record = _console_record(ctx, "verification_log_id, fiduciary_id")
        if not record.get("verification_log_id"):
            raise ApiError(404, "Not Found", "This consent record is not a minor's: it has no guardian verification.")
        row = db.one(
            f"""
            SELECT id, verification_mechanism, provider_name, verification_status, verified_at,
                   {pii.dec_sql("guardian_principal_id_enc")} AS guardian_id,
                   {pii.dec_sql("verification_ref_id_enc")} AS verification_ref_id,
                   {pii.dec_sql("proof_metadata_enc")} AS proof_metadata
            FROM parental_verification_logs WHERE id = %s AND fiduciary_id = %s
            """,
            (*db.bind_key(), *db.bind_key(), *db.bind_key(), record["verification_log_id"], record["fiduciary_id"]),
        )
        if not row:
            raise ApiError(404, "Not Found", "No guardian verification found for this consent record.")
        return {
            "verification_log_id": str(row["id"]),
            "verification_mechanism": row["verification_mechanism"],
            "provider_name": row["provider_name"],
            "verification_status": row["verification_status"],
            "verified_at": row["verified_at"].isoformat() if row.get("verified_at") else None,
            "guardian_id": pii.mask(row["guardian_id"]),
            "verification_ref_id": pii.mask(row["verification_ref_id"]),
            "has_proof_metadata": _has_proof_metadata(row["proof_metadata"]),
            "verification_detail": _verification_detail(row["proof_metadata"]),
        }

    def get_consent_audit_trail(self, ctx: RequestContext) -> dict:
        """Every ledger event about one consent record, grouped by purpose.

        Ported from Consent-Manager (with its f0d65af grouping done here). An
        event belongs to the trail when it is about the record's principal
        (audit user_id = the same pseudonym log_event writes), in the record's
        fiduciary, and names in its context (record_id or consent_record_id)
        this record or one it supersedes, followed back through
        supersedes_record_id. Live and archived years are read. Events group by
        their purpose_id ('ALL' when the row names none); each group lists the
        purpose's name and the data categories it covers in the record's
        policy. The principal id is used only to derive the pseudonym.
        """
        from ..audit import ledger_source, principal_pseudonym
        from .governance import _audited_read
        from .roles import require_audit_access

        _require_console_operator(ctx)
        # The trail is a read of the audit ledger: gated and audited like one (LG-06, R6-c).
        require_audit_access(ctx)
        record = _console_record(
            ctx,
            f"id, fiduciary_id, policy_id, policy_version, language_selected, {pii.dec_sql('user_id_enc')} AS user_id",
            db.bind_key(),
        )
        fid = str(record["fiduciary_id"])
        if not record.get("user_id"):
            # No principal to derive the ledger pseudonym from: nothing can match.
            _audited_read(ctx, [], "get_consent_audit_trail")
            return {"consent_record_id": str(record["id"]), "purposes": []}
        chain = [
            str(r["id"])
            for r in db.all(
                """
                WITH RECURSIVE chain(id, supersedes_record_id) AS (
                    SELECT id, supersedes_record_id FROM consent_records WHERE id = %s AND fiduciary_id = %s
                    UNION
                    SELECT c.id, c.supersedes_record_id FROM consent_records c
                    JOIN chain ON c.id = chain.supersedes_record_id AND c.fiduciary_id = %s
                )
                SELECT id FROM chain
                """,
                (str(record["id"]), fid, fid),
            )
        ]
        policy = db.one(
            "SELECT policy_content FROM consent_policies WHERE id = %s AND fiduciary_id = %s"
            " ORDER BY (version = %s) DESC, effective_date DESC LIMIT 1",
            (record["policy_id"], fid, record["policy_version"] or ""),
        )
        content = (policy or {}).get("policy_content")
        language = str(record.get("language_selected") or "en")
        names = _purpose_names(content, language)
        fields = _purpose_fields(_policy_block(content, language))
        # Narrowed in SQL by a LIKE on each record id (context_details is not
        # always JSON, so it is never cast there); the exact key match is below.
        rows = db.all(
            f"""
            SELECT id, timestamp, audit_action, service_type, service_id, current_log_hash, prev_log_hash,
                   context_details, purpose_id
            FROM {ledger_source()}
            WHERE user_id = %s AND fiduciary_id = %s AND context_details LIKE ANY(%s)
            ORDER BY timestamp, id
            """,
            (principal_pseudonym(record["user_id"]), fid, [f"%{rid}%" for rid in chain]),
        )
        linked = set(chain)
        groups: dict[str, dict] = {}
        for row in rows:
            context = _trail_context(row["context_details"])
            if not isinstance(context, dict) or not any(
                str(context.get(key)) in linked for key in TRAIL_RECORD_KEYS if context.get(key)
            ):
                continue
            purpose = canonical_purpose_id(row["purpose_id"]) if row.get("purpose_id") else TRAIL_ALL
            group = groups.setdefault(
                purpose,
                {
                    "purpose_id": purpose,
                    "purpose_name": "All purposes" if purpose == TRAIL_ALL else names.get(purpose, purpose),
                    "fields": fields.get(purpose, []),
                    "events": [],
                },
            )
            group["events"].append(
                {
                    "timestamp": row["timestamp"].isoformat() if row.get("timestamp") else None,
                    "audit_action": row["audit_action"],
                    "service_type": row["service_type"],
                    "service_id": None if row["service_id"] is None else str(row["service_id"]),
                    "current_log_hash": row["current_log_hash"],
                    "prev_log_hash": row["prev_log_hash"],
                    # Principal keys hold pseudonyms; rows written before they did are masked.
                    "context": pii.payload_view(ctx, context),
                }
            )
        events = [e for g in groups.values() for e in g["events"]]
        _audited_read(ctx, events, "get_consent_audit_trail")
        return db.to_jsonable({"consent_record_id": str(record["id"]), "purposes": list(groups.values())})

    def get_active_consent(self, ctx: RequestContext) -> dict:
        bind_principal_field(ctx, "user_id")
        where = [_USER_MATCH, "fiduciary_id = %s", "is_active_consent IS TRUE"]
        params: list[Any] = [
            *_consent_keys(),
            *pii.hmac_params(require(ctx.payload.get("user_id"), "user_id")),
            _fid(ctx),
        ]
        if ctx.payload.get("policy_id"):
            where.append("policy_id = %s")
            params.append(ctx.payload["policy_id"])
        rows = db.all(
            f"SELECT {_CONSENT_COLUMNS} FROM consent_records WHERE {' AND '.join(where)} ORDER BY timestamp DESC",
            params,
        )
        if not rows:
            raise ApiError(404, "Not Found", "No active consent found.")
        # P11-07: a principal can hold one active record per policy. The top
        # level stays the most recent record (the response shape integrators
        # already read); active_records carries every one of them, so a reader
        # that did not name a policy is never silently handed a partial answer.
        out = _consent_row(ctx, rows[0])
        out["active_records"] = [_consent_row(ctx, r) for r in rows]
        out["active_record_count"] = len(rows)
        return out

    def get_consent_record_details(self, ctx: RequestContext) -> dict:
        # P4-01: the wallet's GET_CONSENT_DETAILS sends policy_id, not record_id.
        # Accept either: record_id reads one record; policy_id reads the
        # principal's active record for that policy.
        bind_principal_field(ctx, "user_id")
        where: list[str] = []
        params: list[Any] = [*_consent_keys()]
        record_id = ctx.payload.get("record_id")
        policy_id = ctx.payload.get("policy_id")
        if record_id:
            where.append("id = %s")
            params.append(record_id)
        elif policy_id:
            # P6-02: the policy_id branch must name a principal. A principal JWT
            # has user_id bound to the token subject by bind_principal_field /
            # authenticate; an integrator key must send an explicit user_id, so a
            # READ key can no longer read an arbitrary principal's active record
            # without naming one.
            where.append(_USER_MATCH)
            where.append("policy_id = %s")
            where.append("is_active_consent IS TRUE")
            params.extend([*pii.hmac_params(require(ctx.payload.get("user_id"), "user_id")), policy_id])
        else:
            raise ApiError(400, "Bad Request", "'record_id' or 'policy_id' is required.")
        if ctx.fiduciary_id:
            where.append("fiduciary_id = %s")
            params.append(ctx.fiduciary_id)
        row = db.one(
            f"SELECT {_CONSENT_COLUMNS} FROM consent_records WHERE {' AND '.join(where)}"
            " ORDER BY timestamp DESC LIMIT 1",
            params,
        )
        if not row:
            raise ApiError(404, "Not Found", "Consent record not found.")
        ensure_principal_owns(ctx, row.get("user_id"), label="Consent record")
        out = _consent_row(ctx, row)
        # P4-01: give the wallet the policy title and persona labels alongside
        # the record, mirroring what GET_POLICY_PURPOSES returns.
        if out is not None:
            policy = db.one(
                "SELECT policy_content FROM consent_policies WHERE id = %s AND fiduciary_id = %s",
                (row["policy_id"], row["fiduciary_id"]),
            )
            content = (policy or {}).get("policy_content") or {}
            lang_block = next(iter(content.values()), {})
            out["policy_title"] = (lang_block.get("title") if isinstance(lang_block, dict) else None) or str(
                row["policy_id"]
            )
            out["personas"] = db.to_jsonable(
                db.all(
                    """
                    SELECT DISTINCT lower(replace(trim(cat), ' ', '_')) AS id, trim(cat) AS label
                    FROM ropa_entries e,
                         LATERAL jsonb_array_elements_text(
                         CASE WHEN jsonb_typeof(e.data_subject_categories) = 'array'
                              THEN e.data_subject_categories ELSE '[]'::jsonb END) AS cat
                    WHERE e.fiduciary_id = %s AND e.linked_policy_ids @> %s AND e.status = 'active'
                      AND trim(cat) <> ''
                    ORDER BY label LIMIT 100
                    """,
                    (str(row["fiduciary_id"]), db.as_jsonb([str(row["policy_id"])])),
                )
            )
            # UD-02 (DD-01): the dashboard substitutes purpose-lifecycle state and
            # the governing retention period for the expiry date the BRD asked
            # for. Surface both so the principal still sees a temporal fact —
            # just the accurate one for an open-ended consent. P7-06: the
            # retention figure comes from the governing retention policy / ROPA
            # (day count), never from an ISO expiry timestamp, and the lifecycle
            # badge reflects the schema's OPEN/CLOSED values.
            from .retention import retention_for_purposes

            lifecycle = {
                canonical_purpose_id(r["purpose_id"]): r["state"]
                for r in db.all(
                    "SELECT purpose_id, state FROM purpose_lifecycle WHERE fiduciary_id = %s",
                    (str(row["fiduciary_id"]),),
                )
            }
            points = [
                (point, point_purpose_id(point))
                for point in row.get("data_point_consents") or []
                if isinstance(point, dict)
            ]
            # P8-07: one batched lookup for every purpose, not 1-2 queries each.
            retention = retention_for_purposes(str(row["fiduciary_id"]), [pid for _p, pid in points if pid])
            purposes: list[dict] = []
            for point, pid in points:
                if not pid:
                    continue
                retention_days, _start = retention[pid]
                purposes.append(
                    {
                        "purpose_id": pid,
                        "name": point.get("purpose_agreed_to") or point.get("name"),
                        # P7-06: report the stored lifecycle state (OPEN/CLOSED)
                        # verbatim; default to OPEN only when no lifecycle row
                        # exists. 'ACTIVE' was never a real schema value.
                        "state": lifecycle.get(pid, "OPEN"),
                        "retention_period_days": retention_days,
                    }
                )
            out["purpose_states"] = purposes
        return out

    def list_consent_history(self, ctx: RequestContext) -> list[dict]:
        bind_principal_field(ctx, "user_id")
        payload = ctx.payload
        page, limit = page_limit(payload)
        where = [_USER_MATCH, "fiduciary_id = %s"]
        params: list[Any] = [*_consent_keys(), *pii.hmac_params(require(payload.get("user_id"), "user_id")), _fid(ctx)]
        # UD-03: search and filter by purpose, date and status.
        if payload.get("purpose_id"):
            where.append(
                # P12-10: the same alias rule as point_purpose_id (an empty
                # data_point_id is skipped), via db/27's tsi_point_purpose.
                "EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(data_point_consents) = 'array' "
                "THEN data_point_consents ELSE '[]'::jsonb END) p WHERE tsi_point_purpose(p) = %s)"
            )
            params.append(canonical_purpose_id(payload["purpose_id"]))
        if payload.get("status"):
            status = str(payload["status"]).upper()
            if status == "ACTIVE":
                where.append("is_active_consent IS TRUE")
            else:
                where.append("consent_status_general = %s")
                params.append(status)
        if payload.get("start_date"):
            where.append("timestamp >= %s::timestamptz")
            params.append(payload["start_date"])
        if payload.get("end_date"):
            where.append("timestamp <= %s::timestamptz")
            params.append(payload["end_date"])
        rows = db.all(
            f"SELECT {_CONSENT_COLUMNS} FROM consent_records WHERE {' AND '.join(where)}"
            " ORDER BY timestamp DESC LIMIT %s OFFSET %s",
            [*params, limit, (page - 1) * limit],
        )
        out = [_consent_row(ctx, row) for row in rows]
        # The wallet sync token is a principal credential: only the principal's own
        # session receives it, never an integrator or console reading the history.
        if ctx.auth_via_principal_jwt:
            for item, row in zip(out, rows, strict=True):
                item["sync_token"] = principal_token(str(item["fiduciary_id"]), row["user_id"])
        return out

    def list_consents(self, ctx: RequestContext) -> dict:
        """Cross-principal consent listing for the DPO console. Always scoped to one fiduciary."""
        payload = ctx.payload
        page, limit = page_limit(payload, 25)
        where = ["fiduciary_id = %s"]
        params: list[Any] = [_fid(ctx)]
        if payload.get("user_id"):
            # The identifier is stored encrypted: the search matches a whole
            # identifier (spaces trimmed, case kept) through its HMAC.
            where.append(_USER_MATCH)
            params.extend(pii.hmac_params(str(payload["user_id"])))
        if payload.get("policy_id"):
            where.append("policy_id = %s")
            params.append(payload["policy_id"])
        if payload.get("status"):
            where.append("consent_status_general = %s")
            params.append(payload["status"])
        if payload.get("active_only"):
            where.append("is_active_consent IS TRUE")
        if payload.get("start_date"):
            where.append("timestamp >= %s::timestamp")
            params.append(payload["start_date"])
        if payload.get("end_date"):
            where.append("timestamp <= %s::timestamp")
            params.append(payload["end_date"])
        clause = " AND ".join(where)
        total = db.one(f"SELECT COUNT(*) AS count FROM consent_records WHERE {clause}", params)
        rows = db.all(
            f"""
            SELECT id AS record_id, {pii.dec_sql("user_id_enc")} AS user_id, policy_id, policy_version,
                   consent_status_general, is_active_consent, timestamp, language_selected, consent_mechanism,
                   jurisdiction, data_point_consents
            FROM consent_records WHERE {clause}
            ORDER BY timestamp DESC LIMIT %s OFFSET %s
            """,
            [*db.bind_key(), *params, limit, (page - 1) * limit],
        )
        out = []
        for row in db.to_jsonable(rows):
            row["user_id"] = pii.principal_view(ctx, row["user_id"])
            points = row.pop("data_point_consents", None) or []
            points = [p for p in points if isinstance(p, dict)]
            row["purposes_total"] = len(points)
            row["purposes_granted"] = sum(1 for p in points if _point_granted(p))
            out.append(row)
        return {"success": True, "data": out, "page": page, "limit": limit, "total": total["count"] if total else 0}

    def export_consent_history(self, ctx: RequestContext) -> str | bytes:
        """UD-04: a principal downloads their consent history as CSV or PDF (format=pdf).

        A principal token is held to its own history. An integrator key may export
        any principal of its own fiduciary — it acts for that fiduciary, which
        answers a principal's access request — but never another tenant's.
        """
        import csv
        import io

        bind_principal_field(ctx, "user_id")
        fid = _fid(ctx)
        user_id = require(ctx.payload.get("user_id"), "user_id")
        rows = db.all(
            f"""
            SELECT cr.timestamp, cr.policy_id, cr.policy_version, cr.language_selected,
                   cr.consent_status_general, cr.is_active_consent, cr.data_point_consents,
                   p.policy_content
            FROM consent_records cr
            LEFT JOIN consent_policies p
                   ON p.id = cr.policy_id AND p.version = cr.policy_version AND p.fiduciary_id = cr.fiduciary_id
            WHERE cr.{_USER_MATCH} AND cr.fiduciary_id = %s
            ORDER BY cr.timestamp DESC
            """,
            (*pii.hmac_params(user_id), fid),
        )
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["timestamp", "policy_id", "policy_version", "language", "status", "active", "purposes"])
        for row in rows:
            points = row.get("data_point_consents") or []
            purposes = ", ".join(
                point_purpose_id(p) + ("" if _point_granted(p) else ":withdrawn") for p in points if isinstance(p, dict)
            )
            writer.writerow(
                [
                    csv_safe(cell)
                    for cell in (
                        row["timestamp"].isoformat() if hasattr(row["timestamp"], "isoformat") else row["timestamp"],
                        row["policy_id"],
                        row["policy_version"],
                        row["language_selected"],
                        row["consent_status_general"],
                        "yes" if row["is_active_consent"] else "no",
                        purposes,
                    )
                ]
            )
        fmt = str(ctx.payload.get("format") or "csv").lower()
        if fmt not in {"csv", "pdf"}:
            raise ApiError(400, "Bad Request", "format must be csv or pdf.")
        log_event(
            user_id,
            fid,
            "APP",
            None,
            "CONSENT_HISTORY_EXPORTED",
            {"rows": len(rows), "format": fmt},
            initiator="PRINCIPAL" if ctx.auth_via_principal_jwt else "INTEGRATOR",
            source_ip=ctx.source_ip,
        )
        if fmt == "pdf":
            from ..pdfgen import text_pdf

            # UD-04: purposes are named in the language the principal consented
            # in (or `language`, if asked), so the export reads in their language.
            language = ctx.payload.get("language")
            lines = [
                # A principal (or their fiduciary's key) sees the id; a console operator a mask.
                f"Principal: {pii.principal_view(ctx, user_id)}",
                f"Generated: {datetime.now(UTC).isoformat()}",
                f"Records: {len(rows)}",
                "",
            ]
            for row in rows:
                lang = str(language or row["language_selected"] or "en")
                names = _purpose_names(row.get("policy_content"), lang)
                stamp = row["timestamp"].isoformat() if hasattr(row["timestamp"], "isoformat") else row["timestamp"]
                lines += [
                    f"{stamp}  {row['consent_status_general']}  ({'active' if row['is_active_consent'] else 'inactive'})",
                    f"  Policy {row['policy_id']} v{row['policy_version']}, language {row['language_selected']}",
                    "  Purposes:",
                ]
                points = [p for p in row.get("data_point_consents") or [] if isinstance(p, dict)]
                for point in points:
                    pid = point_purpose_id(point)
                    name = names.get(pid)
                    label = f"{name} ({pid})" if name and name != pid else pid
                    lines.append(f"    - {label}: {'granted' if _point_granted(point) else 'withdrawn'}")
                if not points:
                    lines.append("    -")
                lines.append("")
            return text_pdf("Consent history", lines)
        return output.getvalue()

    def list_principals(self, ctx: RequestContext) -> list[dict]:
        rows = db.all(
            f"SELECT *, {pii.dec_sql('user_id_enc')} AS user_id, {pii.dec_sql('guardian_id_enc')} AS guardian_id"
            " FROM data_principal WHERE fiduciary_id = %s ORDER BY created_at DESC LIMIT %s",
            (*db.bind_key(), *db.bind_key(), _fid(ctx), int(ctx.payload.get("limit") or 20)),
        )
        return [pii.principal_row(ctx, row, "user_id", "guardian_id") for row in rows]

    def link_user(self, ctx: RequestContext) -> dict:
        reject_principal(ctx, "Linking anonymous sessions requires an application API key.")
        anon = require(ctx.payload.get("anonymous_user_id"), "anonymous_user_id")
        auth = require(ctx.payload.get("authenticated_user_id"), "authenticated_user_id")
        fid = _fid(ctx)
        with db.connection() as conn, conn.cursor() as cur:
            db.allow_consent_maintenance(cur)
            cur.execute(
                f"UPDATE consent_records SET user_id_enc = {pii.ENC_SQL}, user_id_hmac = {pii.HMAC_SQL},"
                f" last_updated_at = NOW() WHERE {_USER_MATCH} AND fiduciary_id = %s",
                (*pii.pid_params(auth), *pii.hmac_params(anon), fid),
            )
        # SEC-05: age_category and verification_status are server-derived from
        # the guardian/consent flows (CC-05), never from this payload. The link
        # only relabels an anonymous profile the server already recorded (age
        # and verification intact) when the authenticated user has none of its
        # own; an existing row is never overwritten, and no default 'ADULT'
        # value is fabricated for a user whose age the server has not attested.
        db.execute(
            f"UPDATE data_principal SET user_id_enc = {pii.ENC_SQL}, user_id_hmac = {pii.HMAC_SQL}"
            f" WHERE {_USER_MATCH} AND fiduciary_id = %s"
            f" AND NOT EXISTS (SELECT 1 FROM data_principal p WHERE p.{_USER_MATCH} AND p.fiduciary_id = %s)",
            (*pii.pid_params(auth), *pii.hmac_params(anon), fid, *pii.hmac_params(auth), fid),
        )
        return {"success": True, "message": "User consent records linked successfully."}

    def validate_consent(self, ctx: RequestContext) -> dict:
        bind_principal_field(ctx, "user_id")
        user_id = require(ctx.payload.get("user_id"), "user_id")
        # P10-04: one canonical spelling for the grant match, the CLOSED gate,
        # the validation row, the webhook and the audit entry alike.
        purpose = canonical_purpose_id(require(ctx.payload.get("required_purpose_id"), "required_purpose_id"))
        if not purpose:
            raise ApiError(400, "Bad Request", "'required_purpose_id' is required.")
        fid = _fid(ctx)
        # CW-03: one active record per policy, so look at all of them. The newest
        # record that names the purpose decides; if none names it, it was never
        # consented to.
        rows = db.all(
            f"""
            SELECT id, data_point_consents, timestamp, consent_status_general, policy_id, policy_version
            FROM consent_records
            WHERE {_USER_MATCH} AND fiduciary_id = %s AND is_active_consent IS TRUE
            ORDER BY timestamp DESC
            """,
            (*pii.hmac_params(user_id), fid),
        )
        valid = False
        purpose_state = "NO_CONSENT"
        row = rows[0] if rows else None
        if rows:
            purpose_state = "NOT_CONSENTED"
            for candidate in rows:
                points = [p for p in candidate.get("data_point_consents") or [] if isinstance(p, dict)]
                named = any(point_purpose_id(p) == canonical_purpose_id(purpose) for p in points)
                if named:
                    row = candidate
                    valid = any(_point_grants(p, purpose) for p in points)
                    purpose_state = "GRANTED" if valid else "WITHDRAWN"
                    break
        # PL-02/PL-03: a CLOSED purpose can never validate — closing one must halt
        # further processing under it even if a consent row still exists.
        # P9-01: matched case-insensitively, exactly as the grant matcher above
        # is; otherwise 'marketing' validates while 'MARKETING' is closed.
        lifecycle = db.one(
            "SELECT state FROM purpose_lifecycle WHERE fiduciary_id = %s AND purpose_id = %s"
            " ORDER BY (state = 'CLOSED') DESC LIMIT 1",
            (fid, purpose),
        )
        if lifecycle and lifecycle["state"] == "CLOSED":
            valid = False
            purpose_state = "PURPOSE_CLOSED"
        # P9-06: a principal checking their own status from the dashboard is
        # not an integrator validation. It must not log a validation, notify
        # the principal of a "denial", webhook the fiduciary or audit as one.
        self_check = bool(ctx.auth_via_principal_jwt)
        if self_check:
            # P10-08: ...but it is still an access to the principal's consent
            # record and is logged as what it is, so Rule 6(1)(c) review can see it.
            log_event(
                user_id,
                fid,
                "APP",
                None,
                "CONSENT_SELF_CHECKED",
                {"purpose_id": purpose, "purpose_status": purpose_state, "valid": valid},
                purpose_id=purpose,
                consent_status="VALID" if valid else "INVALID",
                initiator="PRINCIPAL",
                source_ip=ctx.source_ip,
            )
        else:
            db.execute(
                "INSERT INTO consent_validations (fiduciary_id, user_id_enc, user_id_hmac, purpose_id, status)"
                f" VALUES (%s, {pii.ENC_SQL}, {pii.HMAC_SQL}, %s, %s)",
                (fid, *pii.pid_params(user_id), purpose, "VALID" if valid else "INVALID"),
            )
        # CV-07: a denied validation must notify the principal, and the denial
        # leaves an audit trail with the purpose and outcome as discrete columns
        # (CV-06, LG-02).
        if not valid and not self_check:
            _notify_principal(user_id, fid, NOTIF_VALIDATION_DENIED)
            try:
                from ..webhooks import queue_webhook

                queue_webhook(fid, "CONSENT_DENIED", {"user_id": user_id, "purpose_id": purpose})
            except Exception:  # pragma: no cover
                pass
            log_event(
                user_id,
                fid,
                "APP",
                None,
                "CONSENT_VALIDATION_DENIED",
                {"denied_purpose_id": purpose},
                purpose_id=purpose,
                consent_status="INVALID",
                initiator="INTEGRATOR",
                source_ip=ctx.source_ip,
            )
        # CV-04: return the metadata the decision rests on, so the fiduciary can
        # check timestamp and status itself rather than trusting a bare boolean.
        return {
            "valid": valid,
            "status": "VALID" if valid else "INVALID",
            "required_purpose_id": purpose,
            "metadata": {
                "user_id": user_id,
                "purpose_id": purpose,
                "purpose_status": purpose_state,
                "consent_record_id": str(row["id"]) if row else None,
                "consent_timestamp": row["timestamp"].isoformat() if row and row.get("timestamp") else None,
                "consent_status": row["consent_status_general"] if row else None,
                "policy_id": row["policy_id"] if row else None,
                "policy_version": row["policy_version"] if row else None,
            },
        }

    def get_withdrawal_implications(self, ctx: RequestContext) -> dict:
        """CW-04: what withdrawing each consented purpose means, shown before the
        principal confirms — the service impact, and whether the law requires the
        data to be kept anyway."""
        from .retention import legal_hold_for

        bind_principal_field(ctx, "user_id")
        fid = _fid(ctx)
        user_id = require(ctx.payload.get("user_id"), "user_id")
        language = str(ctx.payload.get("language") or "en")
        where = f"cr.{_USER_MATCH} AND cr.fiduciary_id = %s AND cr.is_active_consent IS TRUE"
        params: list[Any] = [*pii.hmac_params(user_id), fid]
        if ctx.payload.get("policy_id"):
            where += " AND cr.policy_id = %s"
            params.append(ctx.payload["policy_id"])
        # CW-03: one active record per policy; cover every one (newest first).
        records = db.all(
            f"""
            SELECT cr.data_point_consents, p.policy_content
            FROM consent_records cr
            JOIN consent_policies p ON p.id = cr.policy_id AND p.version = cr.policy_version AND p.fiduciary_id = cr.fiduciary_id
            WHERE {where}
            ORDER BY cr.timestamp DESC
            """,
            params,
        )
        if not records:
            raise ApiError(404, "Not Found", "No active consent found.")
        wanted = set(_normalise_purpose_ids(ctx.payload))
        out = []
        seen: set[str] = set()
        granted_points = []
        for record in records:
            content = record.get("policy_content") or {}
            block = content.get(language) or content.get("en") or next(iter(content.values()), {})
            purposes = {
                canonical_purpose_id(p.get("id")): p
                for p in (block.get("data_processing_purposes") or [])
                if isinstance(p, dict)
            }
            for point in record.get("data_point_consents") or []:
                if isinstance(point, dict) and _point_granted(point):
                    granted_points.append((point, purposes))
        for point, purposes in granted_points:
            pid = point_purpose_id(point)
            if (wanted and pid not in wanted) or pid in seen:
                continue
            seen.add(pid)
            purpose = purposes.get(pid, {})
            mandatory = bool(purpose.get("is_mandatory_for_service"))
            hold = legal_hold_for(fid, pid)
            consequence = purpose.get("withdrawal_consequence") or (
                "This purpose is required to provide the service; withdrawing it stops the service that depends on it."
                if mandatory
                else "Processing for this purpose stops. Other purposes and the service are not affected."
            )
            out.append(
                {
                    "purpose_id": pid,
                    "name": purpose.get("name") or pid,
                    "is_mandatory_for_service": mandatory,
                    "consequence": consequence,
                    "data_retained_by_law": bool(hold),
                    "legal_reference": hold["legal_reference"] if hold else None,
                    "retention_days": hold["days"] if hold else None,
                }
            )
        return {"success": True, "language": language, "purposes": out}

    def withdraw_consent(self, ctx: RequestContext) -> dict:
        return self._withdraw(ctx, erasure=False)

    def erasure_request(self, ctx: RequestContext) -> dict:
        return self._withdraw(ctx, erasure=True)

    def _withdraw(self, ctx: RequestContext, erasure: bool) -> dict:
        bind_principal_field(ctx, "user_id")
        fid = _fid(ctx)
        user_id = require(ctx.payload.get("user_id"), "user_id")
        purpose_ids = _normalise_purpose_ids(ctx.payload)
        status = "ERASURE_REQUESTED" if erasure else "WITHDRAWN"
        expiry = (datetime.now(UTC) + timedelta(days=RETENTION_CESSATION_DAYS)).isoformat()
        record_id = None
        held: list[dict] = []
        with db.connection() as conn, conn.cursor() as cur:
            # Legal-hold race: serialise with _set_purge_status for this
            # principal, so a purge being confirmed either sees the hold rows
            # written below or completes before they are. Taken FIRST, before any
            # consent_records row lock, and for plain withdrawals too: the purge
            # path rewrites the same consent_records rows, so both sides take the
            # advisory lock before any row lock and cannot deadlock.
            from .compliance import lock_principal_purges

            lock_principal_purges(cur, fid, pii.normalize(str(user_id)))
            # CW-03: one active record per policy. Withdraw from every active record
            # (optionally only the named policy's) that holds a named purpose.
            policy_filter = ctx.payload.get("policy_id")
            cur.execute(
                f"SELECT * FROM consent_records WHERE {_USER_MATCH} AND fiduciary_id = %s AND is_active_consent IS TRUE"
                + (" AND policy_id = %s" if policy_filter else "")
                + " ORDER BY timestamp DESC FOR UPDATE",
                (*pii.hmac_params(user_id), fid, *([policy_filter] if policy_filter else [])),
            )
            active_rows = cur.fetchall()
            # P9-07 / CW-06: with no active consent there is nothing to withdraw.
            # Succeeding here fired the acknowledgement, webhook, alert and audit
            # cascade for a withdrawal that never happened. An erasure request
            # stays valid after consent was already withdrawn (s.12 right).
            if not active_rows and not erasure:
                raise ApiError(404, "Not Found", "No active consent found to withdraw.")
            if active_rows and purpose_ids:
                # CW-06: every purpose named for withdrawal must currently hold an
                # active grant; withdrawing something that was never granted is an
                # error an integrator can act on, not a silent success.
                granted = {
                    point_purpose_id(p)
                    for active in active_rows
                    for p in active["data_point_consents"] or []
                    if isinstance(p, dict) and _point_granted(p)
                }
                missing = [pid for pid in purpose_ids if pid not in granted]
                if missing:
                    raise ApiError(
                        400,
                        "Bad Request",
                        f"Purpose(s) {sorted(missing)} do not have active consent and cannot be withdrawn.",
                    )
            record_ids: list[str] = []
            for row in active_rows:
                points = row["data_point_consents"] or []
                if purpose_ids and not any(
                    isinstance(p, dict) and _point_granted(p) and point_purpose_id(p) in set(purpose_ids)
                    for p in points
                ):
                    continue  # this policy's record holds none of the named purposes
                full_withdrawal = not purpose_ids
                updated: list[Any] = []
                for point in points:
                    if not isinstance(point, dict):
                        updated.append(point)
                        continue
                    matches = full_withdrawal or point_purpose_id(point) in purpose_ids
                    if matches:
                        point = dict(point)
                        point["consent_granted"] = False
                        point["consent_expiry"] = expiry
                        point["status"] = "withdrawn"
                    updated.append(point)
                remaining = [p for p in updated if isinstance(p, dict) and _point_granted(p)]
                is_active = bool(remaining)
                row_status = status if not remaining else "PARTIAL_WITHDRAWAL"
                # CC-07/CW-07: append, never overwrite. The prior record keeps its
                # purposes exactly as granted and is only retired from "active";
                # the withdrawal is a new record that points back at it.
                observed = _observed_metadata(ctx)
                cur.execute(
                    "UPDATE consent_records SET is_active_consent = FALSE, last_updated_at = NOW() WHERE id = %s",
                    (row["id"],),
                )
                cur.execute(
                    f"""
                    INSERT INTO consent_records
                        (id, user_id_enc, user_id_hmac, fiduciary_id, policy_id, policy_version, timestamp,
                         jurisdiction, language_selected, consent_status_general, consent_mechanism,
                         ip_address_enc, user_agent, data_point_consents, is_active_consent,
                         verification_log_id, session_id, session_source, client_metadata,
                         supersedes_record_id, created_at, last_updated_at)
                    VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, NOW(), %s, %s, %s, %s,
                            {db.enc_expr()}, %s, %s, %s, %s, %s, %s, {_CLIENT_METADATA_SQL}, %s, NOW(), NOW())
                    RETURNING id
                    """,
                    (
                        row["user_id_enc"],
                        row["user_id_hmac"],
                        row["fiduciary_id"],
                        row["policy_id"],
                        row["policy_version"],
                        row["jurisdiction"],
                        row["language_selected"],
                        row_status,
                        observed["mechanism"],
                        *db.bind_encrypt(observed["ip_address"]),
                        observed["user_agent"],
                        db.as_jsonb(updated),
                        is_active,
                        row.get("verification_log_id"),
                        observed["session_id"],
                        observed["session_source"],
                        db.as_jsonb(observed["client_metadata"]),
                        *db.bind_encrypt(observed["claimed_ip_address"]),
                        row["id"],
                    ),
                )
                record_ids.append(str(cur.fetchone()["id"]))
            record_id = record_ids[0] if record_ids else None
            if erasure:
                from .retention import legal_hold_for

                # SEC-04: an erasure filed through an integrator key is bound to a
                # REAL principal. Without this, a WRITE+PURGE key could call
                # erasure_request with any user_id in the tenant — no active
                # consent on file — create a purge row stamped with its own
                # app_id, and then confirm it, reaching erase_cms_copy with no
                # relationship to the subject at all. Require an actual consent
                # record before a key may open an erasure on a principal.
                if ctx.permissions and not ctx.auth_via_principal_jwt:
                    exists = db.one(
                        f"SELECT 1 FROM consent_records WHERE {_USER_MATCH} AND fiduciary_id = %s LIMIT 1",
                        (*pii.hmac_params(user_id), fid),
                    )
                    if not exists:
                        raise ApiError(
                            403,
                            "Forbidden",
                            "This principal has no consent record with this fiduciary; an erasure request must reference a principal the fiduciary actually holds data on.",
                        )

                targets = purpose_ids or ["ALL"]
                # SEC-04: an erasure initiated through an integrator key records
                # which app opened it, so only that processor can later confirm
                # the purge (confirm_purge_status binds to the key's app).
                initiator_app_id = ctx.app_id if ctx.permissions else None
                for target in targets:
                    # CW-11: decide at withdrawal time whether the law requires the
                    # data to be kept; a held request says so and cites the rule.
                    hold = legal_hold_for(fid, target)
                    cur.execute(
                        f"""
                        INSERT INTO purge_requests
                            (user_id_enc, user_id_hmac, fiduciary_id, purpose_id, trigger_event, details, status,
                             legal_reference, hold_until, app_id)
                        VALUES ({pii.ENC_SQL}, {pii.HMAC_SQL}, %s, %s, 'ErasureRequest', %s, %s, %s,
                                CASE WHEN %s::int IS NULL THEN NULL ELSE NOW() + make_interval(days => %s::int) END, %s)
                        """,
                        (
                            *pii.enc_params(user_id),
                            *pii.hmac_params(user_id),
                            fid,
                            target,
                            ctx.payload.get("reason"),
                            "LEGAL_HOLD_APPLIED" if hold else "PENDING",
                            hold["legal_reference"] if hold else None,
                            hold["days"] if hold else None,
                            hold["days"] if hold else None,
                            initiator_app_id,
                        ),
                    )
                    if hold:
                        held.append({"purpose_id": target, "legal_reference": hold["legal_reference"]})
        _notify_principal(user_id, fid, NOTIF_ERASURE_REQUESTED if erasure else NOTIF_WITHDRAWAL_ACK)
        log_event(
            user_id,
            fid,
            "APP",
            None,
            "ERASURE_REQUESTED" if erasure else "CONSENT_WITHDRAWN",
            {"reason": ctx.payload.get("reason"), "purpose_ids": purpose_ids, "record_id": record_id},
            purpose_id=purpose_ids[0] if purpose_ids and len(purpose_ids) == 1 else None,
            consent_status=status,
            initiator="PRINCIPAL" if ctx.auth_via_principal_jwt else "INTEGRATOR",
            source_ip=ctx.source_ip,
        )
        # CW-08: push a stop signal to linked systems instead of relying on them
        # to poll. Delivery happens through the webhook dispatcher worker.
        try:
            from ..webhooks import queue_webhook

            queue_webhook(
                fid,
                "ERASURE_REQUESTED" if erasure else "CONSENT_WITHDRAWN",
                {"user_id": user_id, "purpose_ids": purpose_ids, "consent_record_id": record_id, "erasure": erasure},
            )
        except Exception:  # pragma: no cover
            pass
        # NT-07: withdrawal is the BRD's headline alert event — raise it as an
        # alert the fiduciary must acknowledge, not only a webhook.
        _raise_consent_alert(
            fid,
            "ERASURE_REQUESTED" if erasure else "CONSENT_WITHDRAWN",
            record_id,
            {"user_id": user_id, "purpose_ids": purpose_ids, "legal_holds": held},
        )
        # CW-08: every linked processor is told too, on its own endpoint, and
        # must acknowledge its own alert.
        try:
            from .lifecycle import notify_processors

            processors = notify_processors(
                fid,
                "ERASURE_REQUESTED" if erasure else "CONSENT_WITHDRAWN",
                record_id,
                {"user_id": user_id, "purpose_ids": purpose_ids, "consent_record_id": record_id, "erasure": erasure},
                category="PURGE" if erasure else "NOTIFICATION",
            )
        except Exception:  # pragma: no cover - a fan-out failure never undoes the withdrawal
            processors = []
        out = {
            "success": True,
            "message": "Erasure request submitted." if erasure else "Consent withdrawn successfully.",
            "consent_record_id": record_id,
            "consent_record_ids": record_ids,
            "processors_notified": len(processors),
        }
        if held:
            out["retained_under_legal_hold"] = held
        return out


class PrincipalService(Service):
    def list_active_fiduciaries(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(
            db.all(
                # otp_mode tells the rights portal whether to show "Send OTP".
                """
                SELECT f.id AS fiduciary_id, f.name, f.primary_domain, COALESCE(r.otp_mode, 'EMAIL_OTP') AS otp_mode
                FROM fiduciaries f LEFT JOIN rights_app_config r ON r.fiduciary_id = f.id
                WHERE f.status = 'ACTIVE' ORDER BY f.name
                """
            )
        )

    def list_fiduciary_personas(self, ctx: RequestContext) -> list[dict]:
        """Personas a principal can declare pre-login (Customer, Employee, Vendor...).

        Sourced from the data_subject_categories of the fiduciary's active ROPA
        entries. This is a public, unauthenticated endpoint -- it must never expose
        data_principal rows or any other personal data.
        """
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        return db.to_jsonable(
            db.all(
                """
            SELECT DISTINCT
                   lower(replace(trim(cat), ' ', '_')) AS id,
                   trim(cat)                           AS label
            FROM ropa_entries e,
                 LATERAL jsonb_array_elements_text(
                         CASE WHEN jsonb_typeof(e.data_subject_categories) = 'array'
                              THEN e.data_subject_categories ELSE '[]'::jsonb END) AS cat
            WHERE e.fiduciary_id = %s
              AND e.status = 'active'
              AND trim(cat) <> ''
            ORDER BY label
            LIMIT 100
            """,
                (fid,),
            )
        )

    @staticmethod
    def _otp_mode(fid: str) -> tuple[str, str | None]:
        """The fiduciary's configured OTP mode; 404 for an unknown or inactive fiduciary.

        SEC-14: an unconfigured fiduciary reads EMAIL_OTP (real delivery) rather
        than DUMMY_OTP; the fixed-code evaluation mode is only ever used when an
        operator expressly set it AND allow_dummy_otp permits it."""
        row = db.one(
            """
            SELECT COALESCE(r.otp_mode, 'EMAIL_OTP') AS otp_mode, r.otp_message_template
            FROM fiduciaries f LEFT JOIN rights_app_config r ON r.fiduciary_id = f.id
            WHERE f.id = %s AND f.status = 'ACTIVE'
            """,
            (fid,),
        )
        if not row:
            raise ApiError(404, "Not Found", "Fiduciary not found or inactive.")
        return str(row["otp_mode"]).upper(), row.get("otp_message_template")

    def request_principal_otp(self, ctx: RequestContext) -> dict:
        """Issue a one-time login code and send it to the principal out of band.

        The code is never returned in the response. Only its HMAC is stored, with
        an expiry; principal_login consumes it exactly once.
        """
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        user_id = str(require(ctx.payload.get("user_id"), "user_id")).strip()
        mode, template = self._otp_mode(fid)
        if mode == "DUMMY_OTP":
            if not principal_otp.dummy_allowed():
                raise ApiError(403, "Forbidden", "Evaluation OTP mode is disabled on this deployment.")
            return {"success": True, "message": "Evaluation mode: no OTP is sent."}
        subject = principal_otp.subject_key(fid, user_id)
        recent = db.one(
            "SELECT COUNT(*) AS count FROM principal_otps WHERE subject_hash = %s AND created_at > NOW() - make_interval(mins => %s)",
            (subject, principal_otp.REQUEST_WINDOW_MINUTES),
        )
        if recent and int(recent["count"]) >= principal_otp.MAX_REQUESTS_PER_WINDOW:
            raise ApiError(429, "Too Many Requests", "Too many OTP requests. Please wait and try again.")
        code = principal_otp.generate_code()
        with db.connection() as conn, conn.cursor() as cur:
            # Only the newest code is ever valid.
            cur.execute(
                "UPDATE principal_otps SET consumed_at = NOW() WHERE subject_hash = %s AND consumed_at IS NULL",
                (subject,),
            )
            cur.execute(
                """
                INSERT INTO principal_otps (fiduciary_id, subject_hash, code_hash, expires_at)
                VALUES (%s, %s, %s, NOW() + make_interval(mins => %s))
                """,
                (fid, subject, principal_otp.code_hash(subject, code), principal_otp.TTL_MINUTES),
            )
        # SEC-13: the code is encrypted at enqueue so webhook_deliveries.payload
        # never rests in the clear; the dispatcher decrypts it right before the
        # POST and the message template is rendered only at dispatch time.
        from ..webhooks import queue_webhook

        enc_code = principal_otp.encrypt_code(code)
        message_template = template or "Your verification code is {{otp}}"
        queue_webhook(
            fid,
            "PRINCIPAL_OTP",
            {
                "channel": "EMAIL" if mode == "EMAIL_OTP" else "SMS",
                "recipient": user_id,
                "otp_enc": enc_code,
                "message_template": message_template,
                "expires_in_minutes": principal_otp.TTL_MINUTES,
            },
            category="OTP",
        )
        return {"success": True, "message": "OTP sent.", "expires_in_minutes": principal_otp.TTL_MINUTES}

    def principal_login(self, ctx: RequestContext) -> dict:
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        user_id = str(require(ctx.payload.get("user_id"), "user_id")).strip()
        supplied = str(require(ctx.payload.get("otp"), "otp")).strip()
        mode, _ = self._otp_mode(fid)
        if mode == "DUMMY_OTP":
            if not principal_otp.dummy_allowed() or not principal_otp.dummy_matches(supplied):
                raise ApiError(401, "Unauthorized", "Invalid OTP or account not found.")
        elif not self._consume_otp(fid, user_id, supplied):
            log_event(user_id, fid, "APP", None, "PRINCIPAL_LOGIN_FAILURE", {"reason": "Invalid or expired OTP."})
            raise ApiError(401, "Unauthorized", "Invalid OTP or account not found.")
        log_event(user_id, fid, "APP", None, "PRINCIPAL_LOGIN_SUCCESS", {"otp_mode": mode}, source_ip=ctx.source_ip)
        token = principal_token(fid, user_id)
        # UD-05: the rights portal builds its session from this response
        # (portal.js saveSession). Without the policies the Manage Consent tab
        # read "No active consent policy found" for every principal.
        persona = str(ctx.payload.get("persona") or "").strip()[:100] or None
        return {
            "success": True,
            "token": token,
            "user_id": user_id,
            "fiduciary_id": fid,
            **self._portal_session(fid),
            "persona": persona,
            "sync_token": token,
        }

    @staticmethod
    def _portal_session(fid: str) -> dict:
        """The fiduciary's name, its live policies (with the personas each is
        tagged for in the ROPA) and whether the PCA QR is enabled."""
        fiduciary = db.one(
            "SELECT f.name, r.pca_qr_enabled FROM fiduciaries f"
            " LEFT JOIN rights_app_config r ON r.fiduciary_id = f.id WHERE f.id = %s",
            (fid,),
        )
        rows = db.all(
            """
            SELECT DISTINCT ON (p.id) p.id AS policy_id, p.version, p.jurisdiction, p.policy_content,
                   COALESCE((
                       SELECT jsonb_agg(DISTINCT lower(replace(trim(cat), ' ', '_')))
                       FROM ropa_entries e, LATERAL jsonb_array_elements_text(
                         CASE WHEN jsonb_typeof(e.data_subject_categories) = 'array'
                              THEN e.data_subject_categories ELSE '[]'::jsonb END) AS cat
                       WHERE e.fiduciary_id = p.fiduciary_id AND e.linked_policy_ids @> jsonb_build_array(p.id)
                         AND e.status = 'active' AND trim(cat) <> ''
                   ), '[]'::jsonb) AS personas
            FROM consent_policies p
            WHERE p.fiduciary_id = %s AND p.status = 'ACTIVE' AND p.effective_date <= NOW()
            ORDER BY p.id, p.effective_date DESC
            """,
            (fid,),
        )
        policies = []
        for row in rows:
            content = row.get("policy_content") or {}
            block = (content.get("en") or next(iter(content.values()), {})) if isinstance(content, dict) else {}
            policies.append(
                {
                    "policy_id": row["policy_id"],
                    "version": row["version"],
                    "jurisdiction": row["jurisdiction"],
                    "title": (block.get("title") if isinstance(block, dict) else None) or row["policy_id"],
                    "personas": row.get("personas") or [],
                }
            )
        return {
            "fiduciary_name": (fiduciary or {}).get("name"),
            "policies": policies,
            "pca_qr_enabled": (fiduciary or {}).get("pca_qr_enabled") is not False,
        }

    @staticmethod
    def _consume_otp(fid: str, user_id: str, supplied: str) -> bool:
        """Verify `supplied` against the live code; single-use, expiring, attempt-capped."""
        subject = principal_otp.subject_key(fid, user_id)
        row = db.one(
            """
            SELECT id, code_hash, attempts FROM principal_otps
            WHERE subject_hash = %s AND consumed_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC LIMIT 1
            """,
            (subject,),
        )
        if not row:
            return False
        if principal_otp.code_matches(subject, supplied, row["code_hash"]):
            # Consume atomically: a concurrent second login with the same code loses.
            return (
                db.execute(
                    "UPDATE principal_otps SET consumed_at = NOW() WHERE id = %s AND consumed_at IS NULL",
                    (row["id"],),
                )
                == 1
            )
        # A wrong guess burns an attempt; the code dies once the cap is reached.
        db.execute(
            """
            UPDATE principal_otps SET attempts = attempts + 1,
                   consumed_at = CASE WHEN attempts + 1 >= %s THEN NOW() ELSE consumed_at END
            WHERE id = %s
            """,
            (principal_otp.MAX_ATTEMPTS, row["id"]),
        )
        return False


# Wallet sync actions and the concrete function each one runs. dispatch()
# rewrites _func to the target BEFORE authentication, so the API-key scope map,
# the client allow-list and the admin role gate all judge the real operation -
# a READ-scoped key that sends action=GRANT_CONSENT is checked as record_consent.
WALLET_ACTIONS = {
    "GET_CONSENT_DETAILS": "get_consent_record_details",
    "REVOKE_PURPOSE": "erasure_request",
    "GLOBAL_ERASURE": "erasure_request",
    "GRANT_CONSENT": "record_consent",
    "GET_POLICY_PURPOSES": "get_active_policy",
}


def resolve_wallet_action(payload: dict) -> None:
    """Point a wallet call's _func at the function its `action` runs (in place)."""
    # The wallet client sends the action as `command`; `action` is the documented name.
    action = payload.get("action") or payload.get("command")
    if not action and str(payload.get("_func") or "").upper() in WALLET_ACTIONS:
        action = payload["_func"]
    if not action:
        return
    target = WALLET_ACTIONS.get(str(action).upper())
    if not target:
        raise ApiError(400, "Bad Request", f"Unsupported wallet action: {action}")
    payload["_func"] = target


class WalletService(Service):
    def sync(self, ctx: RequestContext) -> dict:
        return {"success": True}

    def handle(self, ctx: RequestContext) -> Any:
        func = ctx.func
        if func == "sync":
            return self.sync(ctx)
        if func == "get_active_policy":
            from .catalog import PolicyService

            return PolicyService().get_active_policy(ctx)
        if func in set(WALLET_ACTIONS.values()):
            return getattr(ConsentService(), func)(ctx)
        raise ApiError(400, "Bad Request", f"Unsupported function: {func}")
