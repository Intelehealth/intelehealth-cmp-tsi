from __future__ import annotations

from dpdpcms_py.kernel import db
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.netutil import validate_outbound_url
from dpdpcms_py.kernel.service import (
    require,
)
from dpdpcms_py.modules.audit_logging.ledger import (
    log_event,
)


class WebhookConfigHandlers:
    def set_webhook_config(self, ctx: RequestContext) -> dict:
        webhook_url = require(ctx.payload.get("webhook_url"), "webhook_url")
        # SSRF guard at save time: the URL must be http(s) and resolve to a
        # public address. It is re-validated at dispatch time before every POST.
        try:
            validate_outbound_url(webhook_url, "webhook_url")
        except ValueError as exc:
            raise ApiError(400, "Bad Request", str(exc)) from None
        db.execute(
            f"""
            INSERT INTO webhook_configs (fiduciary_id, category, webhook_url, secret_enc, enabled, last_updated_at)
            VALUES (%s, %s, %s, {db.enc_expr()}, %s, NOW())
            ON CONFLICT (fiduciary_id, category) DO UPDATE SET
                webhook_url = EXCLUDED.webhook_url, secret_enc = CASE WHEN %s THEN EXCLUDED.secret_enc ELSE webhook_configs.secret_enc END,
                enabled = EXCLUDED.enabled, last_updated_at = NOW()
            """,
            (
                require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),
                require(ctx.payload.get("category"), "category"),
                webhook_url,
                *db.bind_encrypt(ctx.payload.get("secret", "")),
                bool(ctx.payload.get("enabled", True)),
                # A blank secret on an edit keeps the stored one (the console says so).
                bool(ctx.payload.get("secret")),
            ),
        )
        return {"success": True}

    def set_processor_webhook_config(self, ctx: RequestContext) -> dict:
        """CW-08: a processor's own endpoint, so a withdrawal reaches each
        linked processor instead of one endpoint per category."""
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        app_id = require(ctx.payload.get("app_id"), "app_id")
        category = str(require(ctx.payload.get("category"), "category")).upper()
        if category not in {"NOTIFICATION", "PURGE"}:
            raise ApiError(400, "Bad Request", "category must be NOTIFICATION or PURGE.")
        if not db.one("SELECT 1 FROM apps WHERE id = %s AND fiduciary_id = %s", (app_id, fid)):
            raise ApiError(404, "Not Found", "App not found for this fiduciary.")
        webhook_url = require(ctx.payload.get("webhook_url"), "webhook_url")
        try:
            validate_outbound_url(webhook_url, "webhook_url")
        except ValueError as exc:
            raise ApiError(400, "Bad Request", str(exc)) from None
        db.execute(
            f"""
            INSERT INTO processor_webhook_configs (app_id, fiduciary_id, category, webhook_url, secret_enc, enabled, last_updated_at)
            VALUES (%s, %s, %s, %s, {db.enc_expr()}, %s, NOW())
            ON CONFLICT (app_id, category) DO UPDATE SET
                webhook_url = EXCLUDED.webhook_url, secret_enc = CASE WHEN %s THEN EXCLUDED.secret_enc ELSE processor_webhook_configs.secret_enc END,
                enabled = EXCLUDED.enabled, last_updated_at = NOW()
            """,
            (
                app_id,
                fid,
                category,
                webhook_url,
                *db.bind_encrypt(ctx.payload.get("secret", "")),
                bool(ctx.payload.get("enabled", True)),
                # A blank secret on an edit keeps the stored one (the console says so).
                bool(ctx.payload.get("secret")),
            ),
        )
        log_event(
            ctx.actor_email or "DPO",
            str(fid),
            "DPO_CONSOLE",
            None,
            "PROCESSOR_WEBHOOK_CONFIGURED",
            {"app_id": str(app_id), "category": category, "enabled": bool(ctx.payload.get("enabled", True))},
            source_ip=ctx.source_ip,
        )
        return {"success": True}

    def list_processor_webhook_configs(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(
            db.all(
                """
                SELECT p.app_id, a.name AS app_name, p.category, p.webhook_url, p.enabled, p.last_updated_at
                FROM processor_webhook_configs p JOIN apps a ON a.id = p.app_id
                WHERE p.fiduciary_id = %s ORDER BY a.name, p.category
                """,
                (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),),
            )
        )

    def list_webhook_configs(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(
            db.all(
                "SELECT fiduciary_id, category, webhook_url, enabled, last_updated_at FROM webhook_configs WHERE fiduciary_id = %s",
                (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),),
            )
        )
