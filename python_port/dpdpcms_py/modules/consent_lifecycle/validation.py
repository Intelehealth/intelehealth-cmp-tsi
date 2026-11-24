from __future__ import annotations

from typing import Any

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    bind_principal_field,
    canonical_purpose_id,
    point_purpose_id,
    require,
)
from dpdpcms_py.modules.audit_logging.ledger import log_event
from dpdpcms_py.modules.consent_lifecycle.common import (
    _CONSENT_COLUMNS,
    _USER_MATCH,
    _consent_keys,
    _consent_row,
    _fid,
    _notify_principal,
    _point_granted,
)

NOTIF_VALIDATION_DENIED = "CONSENT_VALIDATION_DENIED"


def _point_grants(point: dict, purpose_id: str) -> bool:
    """As above, for one specific purpose. 'id'/'purpose_id' are older aliases for data_point_id."""
    stored_id = point_purpose_id(point)
    if not stored_id or stored_id != canonical_purpose_id(purpose_id):
        return False
    return _point_granted(point)


class ValidationHandlers:
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
                from dpdpcms_py.modules.notifications.api import queue_webhook

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
