from __future__ import annotations

from dpdpcms_py.kernel import db
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.security import hash_password, random_secret
from dpdpcms_py.kernel.service import (
    Service,
    require,
    tenant_filter,
)

API_KEY_COLUMNS = (
    "ak.id AS key_id, ak.fiduciary_id, ak.app_id, ap.name AS app_name, ak.description, "
    "ak.permissions, ak.status, ak.created_at, ak.expires_at, ak.last_used_at, ak.revoked_at"
)


def api_key_id(payload: dict) -> str:
    """The console and the validator schemas both use 'key_id'; older callers sent 'api_key'."""
    return require(payload.get("key_id") or payload.get("api_key"), "key_id")


class ApiKeyService(Service):
    def generate_api_key(self, ctx: RequestContext) -> dict:
        secret = random_secret()
        fiduciary_id = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        app_id = ctx.payload.get("app_id") or None
        permissions = ctx.payload.get("permissions") or ["READ"]
        if app_id:
            # Rule 6(1)(f): no processor is onboarded without a recorded data
            # processing agreement - a key for an app is issued only once the
            # app carries its DPA reference.
            app = db.one("SELECT dpa_reference FROM apps WHERE id = %s AND fiduciary_id = %s", (app_id, fiduciary_id))
            if not app:
                raise ApiError(404, "Not Found", "App not found for this fiduciary.")
            if not str(app.get("dpa_reference") or "").strip():
                raise ApiError(
                    400,
                    "Bad Request",
                    "This app has no dpa_reference; record its data processing agreement before issuing a key.",
                )
        row = db.insert_returning(
            """
            INSERT INTO api_keys
                (id, key_value, fiduciary_id, app_id, description, permissions, status, created_at, expires_at)
            VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, 'ACTIVE', NOW(), %s)
            RETURNING id
            """,
            (
                hash_password(secret),
                fiduciary_id,
                app_id,
                ctx.payload.get("description"),
                db.as_jsonb(permissions),
                ctx.payload.get("expires_at"),
            ),
        )
        key_id = str(row["id"])
        return {
            "success": True,
            "data": {
                "key_id": key_id,
                "raw_api_key": secret,
                "permissions": permissions,
                "fiduciary_id": fiduciary_id,
                "app_id": app_id,
            },
            # Flat aliases kept for non-console callers.
            "api_key": key_id,
            "api_secret": secret,
        }

    def list_api_keys(self, ctx: RequestContext) -> list[dict]:
        # An empty fiduciary_id/status/search means "no filter" — the console sends "" for all three.
        sql = f"SELECT {API_KEY_COLUMNS} FROM api_keys ak LEFT JOIN apps ap ON ak.app_id = ap.id WHERE 1 = 1"
        params: list[object] = []
        fiduciary_id = (ctx.payload.get("fiduciary_id") or "").strip()
        if fiduciary_id:
            sql += " AND ak.fiduciary_id = %s"
            params.append(fiduciary_id)
        status = (ctx.payload.get("status") or "").strip()
        if status:
            sql += " AND ak.status = %s"
            params.append(status.upper())
        search = (ctx.payload.get("search") or "").strip()
        if search:
            sql += " AND ak.description ILIKE %s"
            params.append(f"%{search}%")
        sql += " ORDER BY ak.created_at DESC"
        return db.to_jsonable(db.all(sql, tuple(params)))

    def revoke_api_key(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        updated = db.execute(
            f"UPDATE api_keys SET status = 'REVOKED', revoked_at = NOW() WHERE id = %s{scope}",
            (api_key_id(ctx.payload), *scope_params),
        )
        if updated == 0:
            raise ApiError(404, "Not Found", "API key not found.")
        return {"success": True, "message": "API Key revoked successfully."}

    def get_api_key_details(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx, "ak.fiduciary_id")
        row = db.one(
            f"SELECT {API_KEY_COLUMNS} FROM api_keys ak LEFT JOIN apps ap ON ak.app_id = ap.id WHERE ak.id = %s{scope}",
            (api_key_id(ctx.payload), *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "API key not found.")
        return db.to_jsonable(row)

    def update_api_key_status(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        updated = db.execute(
            f"UPDATE api_keys SET status = %s WHERE id = %s{scope}",
            (require(ctx.payload.get("status"), "status"), api_key_id(ctx.payload), *scope_params),
        )
        if updated == 0:
            raise ApiError(404, "Not Found", "API key not found.")
        return {"success": True}
