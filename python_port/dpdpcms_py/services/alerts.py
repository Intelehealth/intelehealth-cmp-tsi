from __future__ import annotations

from typing import Any

from .. import db
from ..audit import log_event
from ..context import RequestContext
from ..errors import ApiError
from .base import Service, principal_list_filter, reject_principal, require
from .catalog import resolve_fiduciary

VALID_RECIPIENT_TYPES = {"FIDUCIARY", "PROCESSOR", "PRINCIPAL"}
VALID_ALERT_STATUSES = {"PENDING", "ACKNOWLEDGED", "ESCALATED"}


def enqueue_alert_dispatch(fiduciary_id: str, alert_id: str | None) -> None:
    """Queue delivery side-effects for a raised alert (webhook NOTIFICATION event).

    Called after an alert row exists. The webhook dispatcher worker does the
    actual HMAC-signed delivery on its next cycle.
    """
    if not alert_id:
        return
    try:
        from ..webhooks import queue_webhook

        queue_webhook(fiduciary_id, "ALERT_RAISED", {"alert_id": alert_id}, category="NOTIFICATION")
        db.execute(
            "UPDATE alerts SET attempt_count = attempt_count + 1, last_dispatched_at = NOW() WHERE id = %s",
            (alert_id,),
        )
    except Exception:
        return


class AlertService(Service):
    """Consent-change alerts for fiduciaries and processors (BRD 4.4.2).

    The BRD names the endpoint explicitly — POST /api/v1/client/alerts with
    _func=notify_alert — and requires recipients to confirm they acted
    (acknowledge_alert).
    """

    def notify_alert(self, ctx: RequestContext) -> dict:
        reject_principal(ctx, "Raising alerts requires an application API key.")
        fid = resolve_fiduciary(ctx)
        if not fid:
            raise ApiError(400, "Bad Request", "fiduciary_id is required.")
        recipient_type = str(require(ctx.payload.get("recipient_type"), "recipient_type")).upper()
        if recipient_type not in VALID_RECIPIENT_TYPES:
            raise ApiError(400, "Bad Request", f"recipient_type must be one of {sorted(VALID_RECIPIENT_TYPES)}.")
        alert_type = require(ctx.payload.get("alert_type"), "alert_type")
        row = db.insert_returning(
            """
            INSERT INTO alerts (fiduciary_id, recipient_type, recipient_id, alert_type, event_ref_id, payload, requires_action)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                str(fid),
                recipient_type,
                ctx.payload.get("recipient_id"),
                alert_type,
                ctx.payload.get("event_ref_id"),
                db.as_jsonb(ctx.payload.get("payload") or {}),
                bool(ctx.payload.get("requires_action", True)),
            ),
        )
        alert_id = str(row["id"])
        enqueue_alert_dispatch(str(fid), alert_id)
        log_event(
            ctx.payload.get("user_id"),
            str(fid),
            "APP",
            None,
            "ALERT_RAISED",
            {"alert_id": alert_id, "alert_type": alert_type, "recipient_type": recipient_type},
        )
        return {"success": True, "alert_id": alert_id, "status": "PENDING"}

    def acknowledge_alert(self, ctx: RequestContext) -> dict:
        where = ["id = %s"]
        params: list[Any] = [require(ctx.payload.get("alert_id"), "alert_id")]
        if ctx.fiduciary_id:
            where.append("fiduciary_id = %s")
            params.append(ctx.fiduciary_id)
        if ctx.auth_via_principal_jwt:
            where.append("recipient_type = %s")
            params.append("PRINCIPAL")
            where.append("recipient_id = %s")
            params.append(require(ctx.principal_user_id, "principal"))
        row = db.one(f"SELECT alert_type FROM alerts WHERE {' AND '.join(where)}", params)
        if not row:
            raise ApiError(404, "Not Found", "Alert not found.")
        acknowledged_by = ctx.payload.get("acknowledged_by") or ctx.principal_user_id or ctx.actor_email
        db.execute(
            f"""
            UPDATE alerts SET status = 'ACKNOWLEDGED', acknowledged_at = NOW(),
                              acknowledged_by = %s, last_dispatched_at = NOW()
            WHERE {" AND ".join(where)}
            """,
            [acknowledged_by, *params],
        )
        log_event(
            acknowledged_by,
            ctx.fiduciary_id,
            "APP",
            None,
            "ALERT_ACKNOWLEDGED",
            {"alert_id": params[0], "alert_type": row["alert_type"]},
        )
        return {"success": True, "alert_id": params[0], "status": "ACKNOWLEDGED"}

    def list_alerts(self, ctx: RequestContext) -> list[dict]:
        fid = str(require(resolve_fiduciary(ctx), "fiduciary_id"))
        where = ["fiduciary_id = %s"]
        params: list[Any] = [fid]
        if ctx.auth_via_principal_jwt:
            where.append("recipient_type = %s")
            params.append("PRINCIPAL")
            recipient_id = principal_list_filter(ctx, "recipient_id")
            if recipient_id:
                where.append("recipient_id = %s")
                params.append(recipient_id)
        elif ctx.payload.get("recipient_id"):
            where.append("recipient_id = %s")
            params.append(ctx.payload["recipient_id"])
        if ctx.payload.get("alert_type"):
            where.append("alert_type = %s")
            params.append(ctx.payload["alert_type"])
        if ctx.payload.get("status"):
            status = str(ctx.payload["status"]).upper()
            if status not in VALID_ALERT_STATUSES:
                raise ApiError(400, "Bad Request", f"status must be one of {sorted(VALID_ALERT_STATUSES)}.")
            where.append("status = %s")
            params.append(status)
        params.append(int(ctx.payload.get("limit") or 50))
        return db.to_jsonable(
            db.all(f"SELECT * FROM alerts WHERE {' AND '.join(where)} ORDER BY created_at DESC LIMIT %s", params)
        )
