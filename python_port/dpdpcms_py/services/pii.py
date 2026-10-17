"""reveal_user_id: the one console path to a Data Principal identifier in the clear.

Ported from Consent-Manager's Pii.java. Only a DPO (own fiduciary) or a global
ADMIN holding `pii:reveal` reaches it; API keys and principal tokens never do
(it is not in CLIENT_ALLOWED_FUNCS and the admin category refuses them). Every
reveal is audit-logged, and committed, before the plaintext is returned, and an
operator may reveal at most REVEAL_LIMIT values per rolling REVEAL_WINDOW.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, timedelta
from typing import Any

from .. import audit, db
from .. import pii as crypto
from ..audit import log_event
from ..context import RequestContext
from ..errors import ApiError
from .base import Service, require
from .roles import require_permission

REVEAL_ROLES = {"DPO", "ADMIN"}
REVEAL_LIMIT = 20
REVEAL_WINDOW = timedelta(seconds=60)
REVEAL_ACTION = "PII_REVEALED"
REVEAL_SERVICE_TYPE = "DPO_CONSOLE"

# source -> (table, key column, ((encrypted column, output field), ...), audit-subject column).
# A hardcoded whitelist: no client-supplied value is ever put into SQL text. The
# subject column only names the principal the audit row is about; it is never
# returned. data_principal has no single-row id: it is keyed on user_id_hmac.
SOURCE_MAP: dict[str, tuple[str, str, tuple[tuple[str, str], ...], str]] = {
    "consent_record": (
        "consent_records",
        "id",
        (("user_id_enc", "user_id"), ("ip_address_enc", "ip_address")),
        "user_id_enc",
    ),
    "grievance": ("grievances", "id", (("user_id_enc", "user_id"),), "user_id_enc"),
    "purge_request": ("purge_requests", "id", (("user_id_enc", "user_id"),), "user_id_enc"),
    "data_principal": ("data_principal", "user_id_hmac", (("user_id_enc", "user_id"),), "user_id_enc"),
    # Guardian evidence: the guardian's id and the verification evidence, traced
    # in the audit log to the child principal.
    "parental_verification": (
        "parental_verification_logs",
        "id",
        (
            ("guardian_principal_id_enc", "guardian_id"),
            ("verification_ref_id_enc", "verification_ref_id"),
            ("proof_metadata_enc", "proof_metadata"),
        ),
        "child_principal_id_enc",
    ),
}


def _authorise(ctx: RequestContext) -> str:
    """The fiduciary the caller may reveal in, or 403."""
    role = (ctx.actor_role or "").upper()
    if not ctx.operator_id or ctx.auth_via_principal_jwt or role not in REVEAL_ROLES:
        raise ApiError(403, "Forbidden", "Only a DPO or an administrator may reveal a principal identifier.")
    require_permission(ctx, "pii:reveal")
    fid = str(require(ctx.payload.get("fiduciary_id"), "fiduciary_id"))
    if role != "ADMIN":
        # authenticate() rebinds a DPO's payload fiduciary_id to its own; the
        # tenant it asked for is kept so a cross-tenant request is refused, not
        # silently answered from its own tenant.
        own = str(ctx.fiduciary_id or "")
        asked = str(ctx.requested_fiduciary_id or fid)
        if not own or fid != own or asked != own:
            raise ApiError(403, "Forbidden", "A DPO may only reveal identifiers of its own fiduciary.")
    try:
        uuid.UUID(fid)
    except ValueError:
        raise ApiError(400, "Bad Request", "Invalid 'fiduciary_id'.") from None
    return fid


def _record_key(source: str, payload: dict[str, Any]) -> str:
    if source == "data_principal":
        return str(require(payload.get("user_ref"), "user_ref"))
    key = str(require(payload.get("id"), "id"))
    try:
        uuid.UUID(key)
    except ValueError:
        raise ApiError(400, "Bad Request", "Invalid 'id'.") from None
    return key


def _fetch(source: str, fid: str, key: str) -> dict[str, Any]:
    table, key_column, fields, subject_column = SOURCE_MAP[source]
    columns = [f"{crypto.dec_sql(enc)} AS {name}" for enc, name in fields]
    columns.append(f"{crypto.dec_sql(subject_column)} AS reveal_subject")
    row = db.one(
        f"SELECT {', '.join(columns)} FROM {table} WHERE {key_column} = %s AND fiduciary_id = %s::uuid LIMIT 1",
        (*(db.bind_key() * len(columns)), key, fid),
    )
    if not row:
        raise ApiError(404, "Not Found", "No matching record for the given source, id and fiduciary_id.")
    return row


def _field_value(name: str, value: Any) -> Any:
    if name == "proof_metadata" and value is not None:
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


class PiiService(Service):
    def reveal_user_id(self, ctx: RequestContext) -> dict[str, Any]:
        fid = _authorise(ctx)
        source = ctx.payload.get("source")
        if source not in SOURCE_MAP:
            raise ApiError(400, "Bad Request", "Unknown 'source'.")
        key = _record_key(source, ctx.payload)
        row = _fetch(source, fid, key)
        names = [name for _, name in SOURCE_MAP[source][2]]
        initiator = f"OPERATOR:{ctx.operator_id}"
        # The count and the audit write are serialised per operator, so parallel
        # requests cannot all pass the check before any of them is logged. The
        # audit row is committed by log_event (its own transaction) before the
        # plaintext leaves this method.
        with db.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(hashtext('pii_reveal'), hashtext(%s))", (initiator,))
            since = audit._now().astimezone(UTC).replace(tzinfo=None) - REVEAL_WINDOW
            cur.execute(
                "SELECT COUNT(*) AS n FROM audit_logs WHERE service_type = %s AND timestamp > %s"
                " AND audit_action = %s AND initiator = %s",
                (REVEAL_SERVICE_TYPE, since, REVEAL_ACTION, initiator),
            )
            if cur.fetchone()["n"] >= REVEAL_LIMIT:
                raise ApiError(
                    429, "Too Many Requests", f"Reveal rate limit exceeded ({REVEAL_LIMIT}/min). Try again shortly."
                )
            log_event(
                row["reveal_subject"],
                fid,
                REVEAL_SERVICE_TYPE,
                None,
                REVEAL_ACTION,
                {"source": source, "record_id": key, "fields": names},
                initiator=initiator,
                source_ip=ctx.source_ip,
            )
        return {"source": source, "id": key, "fields": {name: _field_value(name, row[name]) for name in names}}
