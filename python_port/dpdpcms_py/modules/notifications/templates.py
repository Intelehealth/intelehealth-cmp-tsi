from __future__ import annotations

from dpdpcms_py.kernel import db
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    require,
)


class TemplateHandlers:
    def set_notification_message(self, ctx: RequestContext) -> dict:
        # NT-02: a template saved under a name the delivery engine never looks
        # up is a localisation that silently never reaches anyone. Only the
        # types the services write (and DPO-defined breach categories) are
        # accepted. NT-03: messages are keyed by English or an Eighth Schedule
        # language code.
        from dpdpcms_py.modules.notifications.defaults import DEFAULT_NOTIFICATION_MESSAGES, NOTIFICATION_LANGUAGES

        ntype = str(require(ctx.payload.get("notification_type"), "notification_type")).strip().upper()
        if ntype not in DEFAULT_NOTIFICATION_MESSAGES and not ntype.startswith("BREACH_NOTIFICATION"):
            raise ApiError(
                400,
                "Bad Request",
                f"Unknown notification_type '{ntype}'. Use one of {sorted(DEFAULT_NOTIFICATION_MESSAGES)} "
                "or a BREACH_NOTIFICATION_* category.",
            )
        messages = require(ctx.payload.get("messages"), "messages")
        if not isinstance(messages, dict):
            raise ApiError(400, "Bad Request", "messages must be an object keyed by language code.")
        unknown = sorted(str(k) for k in messages if str(k) not in NOTIFICATION_LANGUAGES)
        if unknown:
            raise ApiError(
                400,
                "Bad Request",
                f"Unsupported language code(s) {unknown}; use en or an Eighth Schedule language code.",
            )
        ctx.payload["notification_type"] = ntype
        db.execute(
            """
            INSERT INTO notification_message_templates (fiduciary_id, notification_type, messages, last_updated_at)
            VALUES (%s, %s, %s, NOW())
            ON CONFLICT (fiduciary_id, notification_type) DO UPDATE SET
                messages = EXCLUDED.messages, last_updated_at = NOW()
            """,
            (
                require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),
                require(ctx.payload.get("notification_type"), "notification_type"),
                db.as_jsonb(require(ctx.payload.get("messages"), "messages")),
            ),
        )
        return {"success": True}

    def get_notification_messages(self, ctx: RequestContext) -> list[dict]:
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        rows = db.to_jsonable(
            db.all(
                "SELECT notification_type, messages, last_updated_at FROM notification_message_templates WHERE fiduciary_id = %s ORDER BY notification_type",
                (fid,),
            )
        )
        # P12-07: legacy text db/27 archived (and no longer merges) is shown
        # beside the live type it maps to, so the DPO can re-home it by hand.
        archived: dict[str, list[dict]] = {}
        for row in db.to_jsonable(
            db.all(
                "SELECT notification_type, messages, migrated_to, archived_at FROM notification_message_templates_archive"
                " WHERE fiduciary_id = %s AND migrated_to IS NOT NULL ORDER BY notification_type",
                (fid,),
            )
        ):
            archived.setdefault(str(row.pop("migrated_to")), []).append(row)
        for row in rows:
            row["archived_legacy"] = archived.pop(str(row["notification_type"]), [])
        rows.extend(
            {"notification_type": ntype, "messages": {}, "last_updated_at": None, "archived_legacy": legacy}
            for ntype, legacy in sorted(archived.items())
        )
        return rows
