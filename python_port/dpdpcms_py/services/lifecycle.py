from __future__ import annotations

import uuid as uuidlib
from typing import Any

from .. import db
from ..audit import log_event
from ..context import RequestContext
from ..errors import ApiError
from .base import Service, require

VALID_DURATION_TYPES = {"OPEN_ENDED", "TIME_BOUND"}
VALID_STATES = {"OPEN", "CLOSED"}
VALID_DEIDENTIFICATION_ACTIONS = {"ERASE", "DE_IDENTIFY"}


def _operator_uuid(value: Any) -> str | None:
    """Return a well-formed operator UUID or None (system / unauthenticated actor)."""
    if value is None:
        return None
    try:
        return str(uuidlib.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return None


def extract_purposes(policy_content: Any) -> list[dict[str, Any]]:
    """All purpose objects declared across every language block of a policy."""
    if not isinstance(policy_content, dict):
        return []
    seen: dict[str, dict[str, Any]] = {}
    for block in policy_content.values():
        if not isinstance(block, dict):
            continue
        for purpose in block.get("data_processing_purposes") or []:
            if not isinstance(purpose, dict) or not purpose.get("id"):
                continue
            seen[str(purpose["id"])] = purpose
    return list(seen.values())


def validate_duration_flags(policy_content: Any) -> None:
    """PL-01: every declared purpose must state whether it is open-ended or time-bound.

    The flag lives on the policy JSON so the choice appears in the notice the
    principal reads, not only in an internal decision log. A time-bound purpose
    must carry a positive consent_expiry_days so the lifecycle clock is defined.
    """
    purposes = extract_purposes(policy_content)
    for purpose in purposes:
        pid = purpose["id"]
        duration = str(purpose.get("duration_type") or "").replace("-", "_").upper()
        if duration not in VALID_DURATION_TYPES:
            raise ApiError(
                400,
                "Bad Request",
                f"Purpose '{pid}' must declare duration_type as OPEN_ENDED or TIME_BOUND (DPDP no-expiry policy, PL-01).",
            )
        if duration == "TIME_BOUND":
            days = purpose.get("consent_expiry_days")
            try:
                days = int(days)
            except (TypeError, ValueError):
                raise ApiError(
                    400,
                    "Bad Request",
                    f"Purpose '{pid}' is TIME_BOUND and must declare a positive consent_expiry_days.",
                ) from None
            if days <= 0:
                raise ApiError(
                    400,
                    "Bad Request",
                    f"Purpose '{pid}' is TIME_BOUND and must declare a positive consent_expiry_days.",
                )


def sync_purpose_lifecycle(fiduciary_id: str, policy_content: Any) -> None:
    """Seed/refresh purpose_lifecycle rows from an authored policy.

    New purposes start OPEN; duration metadata is refreshed on each authoring
    pass. Closed purposes are never silently reopened by an edit.
    """
    purposes = extract_purposes(policy_content)
    if not purposes:
        return
    for purpose in purposes:
        pid = str(purpose["id"])
        duration = str(purpose.get("duration_type") or "").replace("-", "_").upper()
        if duration not in VALID_DURATION_TYPES:
            continue
        days = None
        if duration == "TIME_BOUND":
            try:
                days = int(purpose.get("consent_expiry_days"))
            except (TypeError, ValueError):
                days = None
        db.execute(
            """
            INSERT INTO purpose_lifecycle (fiduciary_id, purpose_id, duration_type, consent_expiry_days, state, created_at, last_updated_at)
            VALUES (%s, %s, %s, %s, 'OPEN', NOW(), NOW())
            ON CONFLICT (fiduciary_id, purpose_id) DO UPDATE SET
                duration_type = EXCLUDED.duration_type,
                consent_expiry_days = EXCLUDED.consent_expiry_days,
                last_updated_at = NOW()
            WHERE purpose_lifecycle.state = 'OPEN'
            """,
            (fiduciary_id, pid, duration, days),
        )


def record_alert(fiduciary_id: str, alert_type: str, event_ref_id: str | None = None, payload: dict | None = None) -> str | None:
    """Insert an alert row for a fiduciary (NT-06). Used by close_purpose and the alert API."""
    if not fiduciary_id or not alert_type:
        return None
    try:
        row = db.insert_returning(
            """
            INSERT INTO alerts (fiduciary_id, recipient_type, recipient_id, alert_type, event_ref_id, payload)
            VALUES (%s, 'FIDUCIARY', %s, %s, %s, %s)
            RETURNING id
            """,
            (str(fiduciary_id), str(fiduciary_id), alert_type, event_ref_id, db.as_jsonb(payload or {})),
        )
        return str(row["id"]) if row else None
    except Exception:
        return None


def close_purpose_exec(
    fiduciary_id: str,
    purpose_id: str,
    reason: str | None = None,
    deidentification_action: str = "ERASE",
    closed_by: str | None = None,
) -> dict[str, Any]:
    """PL-03: close a purpose and trigger erasure / de-identification of data held under it.

    This is the replacement for consent expiry. Closing a purpose:
      1. marks purpose_lifecycle CLOSED (with reason / actor / action),
      2. raises PURGE requests for every principal whose active consent grants it,
      3. notifies each affected principal,
      4. raises an alert for the fiduciary and queues a PURGE webhook,
      5. records the event in the immutable audit log.
    """
    if not fiduciary_id or not purpose_id:
        raise ApiError(400, "Bad Request", "fiduciary_id and purpose_id are required.")
    purpose_id = str(purpose_id)
    action = str(deidentification_action or "ERASE").replace("-", "_").upper()
    if action not in VALID_DEIDENTIFICATION_ACTIONS:
        raise ApiError(400, "Bad Request", f"deidentification_action must be one of {sorted(VALID_DEIDENTIFICATION_ACTIONS)}.")

    row = db.one(
        "SELECT purpose_id, state FROM purpose_lifecycle WHERE fiduciary_id = %s AND purpose_id = %s",
        (fiduciary_id, purpose_id),
    )
    if not row:
        raise ApiError(404, "Not Found", f"Purpose '{purpose_id}' is not declared in any policy for this fiduciary.")
    if row["state"] == "CLOSED":
        raise ApiError(409, "Conflict", f"Purpose '{purpose_id}' is already closed.")

    # Distinct principals who currently hold an active grant for this purpose.
    holders = db.all(
        """
        SELECT DISTINCT cr.user_id
        FROM consent_records cr,
             LATERAL jsonb_array_elements(cr.data_point_consents) AS p
        WHERE cr.fiduciary_id = %s
          AND cr.is_active_consent IS TRUE
          AND p ->> 'data_point_id' = %s
          AND (
                p ->> 'consent_granted' = 'true'
                OR lower(p ->> 'status') IN ('granted', 'consent_given')
              )
        """,
        (fiduciary_id, purpose_id),
    )
    principals = {str(h["user_id"]) for h in holders}

    # PL-03: closure and the retention sweep must agree. When a retention period
    # governs this purpose (configured policy, else the ROPA — the same lookup the
    # sweep uses), closure starts that clock and the sweep raises the purge when
    # it elapses; only an unretained purpose is purged at closure.
    from ..jobs import _retention_for

    retention_days, _start = _retention_for(fiduciary_id, purpose_id)
    created = 0
    skipped = 0
    actor = _operator_uuid(closed_by)
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE purpose_lifecycle
            SET state = 'CLOSED', closed_at = NOW(), closed_by = %s, closure_reason = %s,
                deidentification_action = %s, last_updated_at = NOW()
            WHERE fiduciary_id = %s AND purpose_id = %s
            """,
            (actor, reason, action, fiduciary_id, purpose_id),
        )
        for user_id in principals:
            if retention_days:
                cur.execute(
                    """
                    INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type)
                    VALUES ('PRINCIPAL', %s, %s, 'PURPOSE_CLOSED')
                    """,
                    (user_id, fiduciary_id),
                )
                continue
            cur.execute(
                """
                SELECT 1 FROM purge_requests
                WHERE user_id = %s AND fiduciary_id = %s AND purpose_id = %s
                  AND trigger_event = 'PurposeClosed' AND status IN ('PENDING', 'IN_PROGRESS')
                LIMIT 1
                """,
                (user_id, fiduciary_id, purpose_id),
            )
            existing = cur.fetchone()
            if existing:
                skipped += 1
                continue
            cur.execute(
                """
                INSERT INTO purge_requests (user_id, fiduciary_id, purpose_id, trigger_event, details, action)
                VALUES (%s, %s, %s, 'PurposeClosed', %s, %s)
                """,
                (user_id, fiduciary_id, purpose_id, reason, action),
            )
            created += 1
            cur.execute(
                """
                INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type)
                VALUES ('PRINCIPAL', %s, %s, 'PURPOSE_CLOSED')
                """,
                (user_id, fiduciary_id),
            )

    try:
        from .alerts import enqueue_alert_dispatch  # local import to avoid a cycle
    except ImportError:  # pragma: no cover - alerts module is present at runtime
        enqueue_alert_dispatch = None

    alert_id = record_alert(fiduciary_id, "PURPOSE_CLOSED", purpose_id, {"purpose_id": purpose_id, "reason": reason})
    try:
        from ..webhooks import queue_webhook

        queue_webhook(
            fiduciary_id,
            "PURPOSE_CLOSED",
            {"purpose_id": purpose_id, "action": action, "retention_days": retention_days},
            category="PURGE",
        )
    except Exception:  # pragma: no cover
        pass
    if enqueue_alert_dispatch:
        try:
            enqueue_alert_dispatch(fiduciary_id, alert_id)
        except Exception:  # pragma: no cover
            pass

    log_event(
        closed_by or "DPO",
        fiduciary_id,
        "DPO_CONSOLE",
        None,
        "PURPOSE_CLOSED",
        {"purpose_id": purpose_id, "action": action, "principals_affected": len(principals), "purge_requests": created},
    )
    return {
        "success": True,
        "purpose_id": purpose_id,
        "state": "CLOSED",
        "deidentification_action": action,
        "principals_affected": len(principals),
        "purge_requests_created": created,
        "purge_requests_skipped": skipped,
        # Non-null = data is kept for this many days from closure, then purged by the sweep.
        "retention_deferred_days": retention_days,
        "alert_id": alert_id,
    }


class PurposeLifecycleService(Service):
    """Purpose lifecycle state — the Intelehealth substitute for consent renewal."""

    def list_purpose_lifecycle(self, ctx: RequestContext) -> list[dict]:
        fid = require(ctx.payload.get("fiduciary_id") or ctx.fiduciary_id, "fiduciary_id")
        where = ["fiduciary_id = %s"]
        params: list[Any] = [str(fid)]
        if ctx.payload.get("state"):
            state = str(ctx.payload["state"]).upper()
            if state not in VALID_STATES:
                raise ApiError(400, "Bad Request", "state must be OPEN or CLOSED.")
            where.append("state = %s")
            params.append(state)
        if ctx.payload.get("purpose_id"):
            where.append("purpose_id = %s")
            params.append(ctx.payload["purpose_id"])
        params.append(int(ctx.payload.get("limit") or 100))
        return db.to_jsonable(
            db.all(
                f"SELECT * FROM purpose_lifecycle WHERE {' AND '.join(where)} ORDER BY created_at DESC LIMIT %s",
                params,
            )
        )

    def set_purpose_state(self, ctx: RequestContext) -> dict:
        """PL-02: hold the open/closed state of a purpose."""
        fid = str(require(ctx.payload.get("fiduciary_id") or ctx.fiduciary_id, "fiduciary_id"))
        purpose_id = require(ctx.payload.get("purpose_id"), "purpose_id")
        state = str(require(ctx.payload.get("state"), "state")).upper()
        if state not in VALID_STATES:
            raise ApiError(400, "Bad Request", "state must be OPEN or CLOSED.")
        from .admin import authenticated_user_id

        actor = authenticated_user_id(ctx)
        if state == "CLOSED":
            return close_purpose_exec(
                fid,
                purpose_id,
                reason=ctx.payload.get("reason"),
                deidentification_action=ctx.payload.get("deidentification_action", "ERASE"),
                closed_by=actor,
            )
        row = db.one(
            "SELECT state FROM purpose_lifecycle WHERE fiduciary_id = %s AND purpose_id = %s", (fid, purpose_id)
        )
        if not row:
            raise ApiError(404, "Not Found", f"Purpose '{purpose_id}' is not declared for this fiduciary.")
        if row["state"] == "OPEN":
            raise ApiError(409, "Conflict", f"Purpose '{purpose_id}' is already open.")
        db.execute(
            "UPDATE purpose_lifecycle SET state = 'OPEN', closed_at = NULL, closure_reason = NULL, deidentification_action = NULL, last_updated_at = NOW() WHERE fiduciary_id = %s AND purpose_id = %s",
            (fid, purpose_id),
        )
        log_event(actor or "DPO", fid, "DPO_CONSOLE", None, "PURPOSE_REOPENED", {"purpose_id": purpose_id})
        return {"success": True, "purpose_id": purpose_id, "state": "OPEN"}

    def close_purpose(self, ctx: RequestContext) -> dict:
        """PL-03: close a purpose and trigger erasure/de-identification of data held under it."""
        fid = str(require(ctx.payload.get("fiduciary_id") or ctx.fiduciary_id, "fiduciary_id"))
        from .admin import authenticated_user_id

        return close_purpose_exec(
            fid,
            require(ctx.payload.get("purpose_id"), "purpose_id"),
            reason=ctx.payload.get("reason"),
            deidentification_action=ctx.payload.get("deidentification_action", "ERASE"),
            closed_by=authenticated_user_id(ctx),
        )