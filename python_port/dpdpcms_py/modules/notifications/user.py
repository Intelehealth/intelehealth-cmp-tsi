from __future__ import annotations

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    bind_principal_field,
    principal_list_filter,
    require,
)
from dpdpcms_py.modules.administration.api import resolve_fiduciary
from dpdpcms_py.modules.audit_logging.ledger import (
    log_event,
)


class UserNotificationHandlers:
    def list_notifications(self, ctx: RequestContext) -> list[dict]:
        bind_principal_field(ctx, "user_id")
        recipient = principal_list_filter(ctx, "recipient_id") or ctx.payload.get("user_id")
        where = ["fiduciary_id = %s"]
        params = [require(resolve_fiduciary(ctx), "fiduciary_id")]
        if ctx.auth_via_principal_jwt:
            where.append("recipient_type = %s")
            params.append("PRINCIPAL")
        if recipient:
            where.append(pii.match_sql("recipient_id"))
            params.extend(pii.hmac_params(recipient))
        params.append(int(ctx.payload.get("limit") or 50))
        rows = db.all(
            f"SELECT *, {pii.dec_sql('recipient_id_enc')} AS recipient_id FROM notifications"
            f" WHERE {' AND '.join(where)} ORDER BY created_at DESC LIMIT %s",
            [*db.bind_key(), *params],
        )
        return [pii.recipient_row(ctx, row, "recipient_id") for row in rows]

    def mark_notification_read(self, ctx: RequestContext) -> dict:
        # NT-05: the schema and the documented sample name the field `id`; older
        # callers send `notification_id`. Accept either.
        nid = require(ctx.payload.get("notification_id") or ctx.payload.get("id"), "notification_id")
        where = ["id = %s"]
        params: list = [nid]
        if ctx.fiduciary_id:
            where.append("fiduciary_id = %s")
            params.append(ctx.fiduciary_id)
        if ctx.auth_via_principal_jwt:
            where.append("recipient_type = %s")
            params.append("PRINCIPAL")
            where.append(pii.match_sql("recipient_id"))
            params.extend(pii.hmac_params(require(ctx.principal_user_id, "principal")))
        read = db.execute(f"UPDATE notifications SET read_at = NOW() WHERE {' AND '.join(where)}", params)
        if read:
            row = db.one(
                f"SELECT {pii.dec_sql('recipient_id_enc')} AS recipient_id, fiduciary_id FROM notifications WHERE id = %s",
                (*db.bind_key(), nid),
            )
            if row:
                log_event(
                    row.get("recipient_id") or ctx.actor_email or "PRINCIPAL",
                    row["fiduciary_id"],
                    "APP",
                    # P9-03: the resolved id, never payload['notification_id'],
                    # which is absent when the caller uses the schema's 'id'.
                    str(nid),
                    "NOTIFICATION_ACKNOWLEDGED",
                    {"notification_id": str(nid)},
                    initiator="PRINCIPAL" if ctx.auth_via_principal_jwt else "INTEGRATOR",
                    source_ip=ctx.source_ip,
                )
        return {"success": True}

    def dispatch_notification(self, ctx: RequestContext) -> dict:
        # P10-10: the caller supplies the values the template's placeholders
        # need (`context`; `payload_data` is the older name), so a dispatched
        # notice is filled like one the services raise.
        context = ctx.payload.get("context") or ctx.payload.get("payload_data")
        if context is not None and not isinstance(context, dict):
            raise ApiError(400, "Bad Request", "context must be an object.")
        row = db.insert_returning(
            "INSERT INTO notifications (id, recipient_type, recipient_id_enc, recipient_id_hmac, fiduciary_id,"
            f" notification_type, context, created_at) VALUES (uuid_generate_v4(), %s, {pii.PID_VALUES}, %s, %s, %s, NOW())"
            " RETURNING id",
            (
                require(ctx.payload.get("recipient_type"), "recipient_type"),
                *pii.pid_params(str(require(ctx.payload.get("recipient_id"), "recipient_id"))),
                require(resolve_fiduciary(ctx), "fiduciary_id"),
                require(ctx.payload.get("notification_type") or ctx.payload.get("template_id"), "notification_type"),
                db.as_jsonb(context) if context else None,
            ),
        )
        return {"success": True, "notification_id": str(row["id"])}
