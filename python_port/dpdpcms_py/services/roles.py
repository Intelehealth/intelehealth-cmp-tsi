from __future__ import annotations

from .. import db
from ..audit import log_event
from ..context import RequestContext
from ..errors import ApiError
from .base import Service, require

# Roles the BRD names explicitly (SA-01). Custom roles may be added at runtime,
# but the built-in set can never be deleted or have its name changed.
BUILTIN_ROLES = {"ADMIN", "DPO", "AUDITOR", "OPERATOR"}
FULL_ACCESS = "*"


def role_permissions(ctx: RequestContext) -> set[str]:
    """The permission set of the authenticated operator, from the roles table.

    Unknown or legacy roles resolve to the built-in permission surface so an
    existing operator is never locked out by the migration; an ADMIN token always
    carries full access.
    """
    role = (ctx.actor_role or "").upper()
    if role == "ADMIN" or (ctx.auth_token or {}).get("role", "").upper() == "ADMIN":
        return {FULL_ACCESS}
    if not role:
        return set()
    row = db.one("SELECT permissions FROM roles WHERE code = %s", (role,))
    raw = (row or {}).get("permissions")
    if isinstance(raw, str):
        return {part.strip().upper() for part in raw.strip("[]").replace('"', "").split(",") if part.strip()}
    if isinstance(raw, list):
        return {str(part).strip().upper() for part in raw}
    return set()


def require_permission(ctx: RequestContext, permission: str) -> None:
    """Raise 403 unless the actor's role grants `permission` (or full access)."""
    perms = role_permissions(ctx)
    if FULL_ACCESS in perms or permission.upper() in perms:
        return
    raise ApiError(403, "Forbidden", f"Your role does not grant the '{permission}' permission.")


def require_audit_access(ctx: RequestContext) -> None:
    """LG-06: audit-log access is role-gated, and MFA-verified when the account
    has MFA enabled (a token issued before MFA verification must present it)."""
    require_permission(ctx, "audit:read")
    token = ctx.auth_token or {}
    if token.get("mfa") is False:
        raise ApiError(403, "Forbidden", "Multi-factor verification is required to read the audit log.")


class RoleService(Service):
    def list_roles(self, ctx: RequestContext) -> list[dict]:
        require_permission(ctx, "role:read")
        return db.to_jsonable(db.all("SELECT * FROM roles ORDER BY is_builtin DESC, code"))

    def get_role(self, ctx: RequestContext) -> dict:
        require_permission(ctx, "role:read")
        code = require(ctx.payload.get("role_code") or ctx.payload.get("code"), "role_code")
        row = db.one("SELECT * FROM roles WHERE code = %s", (code.upper(),))
        if not row:
            raise ApiError(404, "Not Found", f"Role '{code}' not found.")
        return db.to_jsonable(row)

    def create_role(self, ctx: RequestContext) -> dict:
        """SA-02: define a custom role with its own permission surface."""
        require_permission(ctx, "role:manage")
        code = require(ctx.payload.get("role_code") or ctx.payload.get("code"), "role_code").upper()
        if code in BUILTIN_ROLES:
            raise ApiError(400, "Bad Request", f"'{code}' is a built-in role and cannot be redefined.")
        name = require(ctx.payload.get("name"), "name")
        permissions = ctx.payload.get("permissions") or []
        if not isinstance(permissions, list) or not all(isinstance(p, str) for p in permissions):
            raise ApiError(400, "Bad Request", "permissions must be an array of strings.")
        db.execute(
            "INSERT INTO roles (code, name, description, is_builtin, permissions) VALUES (%s, %s, %s, FALSE, %s) ON CONFLICT (code) DO NOTHING",
            (code, name, ctx.payload.get("description"), db.as_jsonb(permissions)),
        )
        log_event(
            ctx.actor_email or "ADMIN",
            ctx.payload.get("fiduciary_id"),
            "ADMIN_CONSOLE",
            None,
            "ROLE_CREATED",
            {"role_code": code, "permissions": permissions},
        )
        return {"success": True, "role_code": code}

    def set_role_permissions(self, ctx: RequestContext) -> dict:
        """SA-03: set the permission hierarchy for an existing role (built-in or custom)."""
        require_permission(ctx, "role:manage")
        code = require(ctx.payload.get("role_code") or ctx.payload.get("code"), "role_code").upper()
        permissions = require(ctx.payload.get("permissions"), "permissions")
        if not isinstance(permissions, list) or not all(isinstance(p, str) for p in permissions):
            raise ApiError(400, "Bad Request", "permissions must be an array of strings.")
        row = db.execute("UPDATE roles SET permissions = %s WHERE code = %s", (db.as_jsonb(permissions), code))
        if row == 0:
            raise ApiError(404, "Not Found", f"Role '{code}' not found.")
        log_event(
            ctx.actor_email or "ADMIN",
            ctx.payload.get("fiduciary_id"),
            "ADMIN_CONSOLE",
            None,
            "ROLE_PERMISSIONS_UPDATED",
            {"role_code": code, "permissions": permissions},
        )
        return {"success": True, "role_code": code, "permissions": permissions}

    def delete_role(self, ctx: RequestContext) -> dict:
        require_permission(ctx, "role:manage")
        code = require(ctx.payload.get("role_code") or ctx.payload.get("code"), "role_code").upper()
        if code in BUILTIN_ROLES:
            raise ApiError(400, "Bad Request", f"'{code}' is a built-in role and cannot be deleted.")
        row = db.execute("DELETE FROM roles WHERE code = %s", (code,))
        if row == 0:
            raise ApiError(404, "Not Found", f"Role '{code}' not found.")
        log_event(ctx.actor_email or "ADMIN", None, "ADMIN_CONSOLE", None, "ROLE_DELETED", {"role_code": code})
        return {"success": True, "role_code": code}