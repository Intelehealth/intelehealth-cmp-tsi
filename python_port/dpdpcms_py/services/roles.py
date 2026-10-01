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

# Admin functions every signed-in operator may call regardless of role: the MFA
# round-trip on their own account and logout. They are also the only functions
# a not-yet-MFA-verified session may reach.
MFA_EXEMPT_FUNCS = {"verify_mfa", "enrol_mfa", "logout"}

# SA-02/SA-03: the permission an admin-category call needs is <resource>:<action>.
# The resource comes from the service; the action from the function name.
SERVICE_RESOURCES = {
    "operator": "operator",
    "admindash": "dashboard",
    "fiduciary": "fiduciary",
    "app": "app",
    "apikey": "apikey",
    "policy": "policy",
    "consent": "consent",
    "wallet": "consent",
    "compliance": "purge",
    "grievance": "grievance",
    "breach": "breach",
    "notification": "notification",
    "audit": "audit",
    "job": "job",
    "ropa": "ropa",
    "legal": "legal",
    "rights": "rights",
    "alerts": "alert",
    "purpose": "purpose",
    "retention": "retention",
    "role": "role",
}
READ_PREFIXES = ("list_", "get_", "validate_", "download_", "export_")
FUNC_PERMISSIONS = {
    ("admindash", "list_access_logs"): "audit:read",
    ("role", "create_role"): "role:manage",
    ("role", "set_role_permissions"): "role:manage",
    ("role", "delete_role"): "role:manage",
}
# A higher action implies the lower ones on the same resource.
ACTION_IMPLIES = {"manage": {"manage", "write", "read"}, "write": {"write", "read"}, "read": {"read"}}


def required_permission(service: str, func: str) -> str | None:
    """The permission string an admin-category (service, func) call requires."""
    if func in MFA_EXEMPT_FUNCS:
        return None
    override = FUNC_PERMISSIONS.get((service, func))
    if override:
        return override
    # An unmapped service (setup, principal...) resolves to a resource no seeded
    # role holds, so only full access reaches it.
    resource = SERVICE_RESOURCES.get(service, service)
    action = "read" if func.startswith(READ_PREFIXES) else "write"
    return f"{resource}:{action}"


def has_permission(perms: set[str], permission: str) -> bool:
    if FULL_ACCESS in perms or permission in perms:
        return True
    resource, _, action = permission.partition(":")
    if f"{resource}:*" in perms:
        return True
    return any(f"{resource}:{held}" in perms for held, implied in ACTION_IMPLIES.items() if action in implied)


def _parse_permissions(raw: object) -> set[str]:
    if isinstance(raw, str):
        return {part.strip().lower() for part in raw.strip("[]").replace('"', "").split(",") if part.strip()}
    if isinstance(raw, list):
        return {str(part).strip().lower() for part in raw}
    return set()


def role_permissions(ctx: RequestContext) -> set[str]:
    """The permission set of the authenticated operator, from the roles table.

    A tenant-scoped role (roles.fiduciary_id = the operator's fiduciary) takes
    precedence over the global role of the same code. ADMIN always carries full
    access; an unknown role carries none.
    """
    role = (ctx.actor_role or "").upper()
    if role == "ADMIN":
        return {FULL_ACCESS}
    if not role:
        return set()
    row = db.one(
        """
        SELECT permissions FROM roles
        WHERE code = %s AND (fiduciary_id = %s::uuid OR fiduciary_id IS NULL)
        ORDER BY fiduciary_id NULLS LAST
        LIMIT 1
        """,
        (role, ctx.fiduciary_id),
    )
    return _parse_permissions((row or {}).get("permissions"))


def require_permission(ctx: RequestContext, permission: str) -> None:
    """Raise 403 unless the actor's role grants `permission` (or full access)."""
    if has_permission(role_permissions(ctx), permission.lower()):
        return
    raise ApiError(403, "Forbidden", f"Your role does not grant the '{permission}' permission.")


def enforce_role_permission(ctx: RequestContext) -> None:
    """Gate an authenticated admin-category call on the roles table."""
    permission = required_permission(ctx.service, ctx.func)
    if permission:
        require_permission(ctx, permission)


def require_audit_access(ctx: RequestContext) -> None:
    """LG-06: audit-log access is role-gated, and MFA-verified when the account
    has MFA enabled (a token issued before MFA verification must present it)."""
    require_permission(ctx, "audit:read")
    token = ctx.auth_token or {}
    if token.get("mfa") is False:
        raise ApiError(403, "Forbidden", "Multi-factor verification is required to read the audit log.")


def _validate_permissions(ctx: RequestContext, permissions: object) -> list[str]:
    if not isinstance(permissions, list) or not all(isinstance(p, str) for p in permissions):
        raise ApiError(400, "Bad Request", "permissions must be an array of strings.")
    cleaned = [p.strip().lower() for p in permissions if p.strip()]
    # A tenant-scoped actor can only delegate what it already holds, so a custom
    # role can never be used to climb above the creator's own access.
    if ctx.fiduciary_id:
        held = role_permissions(ctx)
        excess = [p for p in cleaned if p == FULL_ACCESS or not has_permission(held, p)]
        if excess:
            raise ApiError(403, "Forbidden", f"You cannot grant permissions you do not hold: {', '.join(excess)}.")
    return cleaned


def _role_scope(ctx: RequestContext) -> str | None:
    """The fiduciary a role write applies to: the caller's own tenant, or for a
    global ADMIN the payload's fiduciary_id (None = a global role)."""
    return ctx.fiduciary_id or ctx.payload.get("fiduciary_id") or None


class RoleService(Service):
    def list_roles(self, ctx: RequestContext) -> list[dict]:
        require_permission(ctx, "role:read")
        if ctx.fiduciary_id:
            rows = db.all(
                "SELECT * FROM roles WHERE fiduciary_id IS NULL OR fiduciary_id = %s ORDER BY is_builtin DESC, code",
                (ctx.fiduciary_id,),
            )
        else:
            rows = db.all("SELECT * FROM roles ORDER BY is_builtin DESC, code")
        return db.to_jsonable(rows)

    def get_role(self, ctx: RequestContext) -> dict:
        require_permission(ctx, "role:read")
        code = require(ctx.payload.get("role_code") or ctx.payload.get("code"), "role_code").upper()
        row = db.one(
            """
            SELECT * FROM roles
            WHERE code = %s AND (fiduciary_id = %s::uuid OR fiduciary_id IS NULL)
            ORDER BY fiduciary_id NULLS LAST LIMIT 1
            """,
            (code, _role_scope(ctx)),
        )
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
        permissions = _validate_permissions(ctx, ctx.payload.get("permissions") or [])
        scope = _role_scope(ctx)
        if db.one("SELECT 1 FROM roles WHERE code = %s AND fiduciary_id IS NOT DISTINCT FROM %s::uuid", (code, scope)):
            raise ApiError(409, "Conflict", f"Role '{code}' already exists.")
        db.execute(
            "INSERT INTO roles (code, name, description, is_builtin, permissions, fiduciary_id) VALUES (%s, %s, %s, FALSE, %s, %s)",
            (code, name, ctx.payload.get("description"), db.as_jsonb(permissions), scope),
        )
        log_event(
            ctx.actor_email or "ADMIN",
            scope,
            "ADMIN_CONSOLE",
            None,
            "ROLE_CREATED",
            {"role_code": code, "permissions": permissions},
        )
        return {"success": True, "role_code": code}

    def set_role_permissions(self, ctx: RequestContext) -> dict:
        """SA-03: set the permission hierarchy for an existing role (built-in or custom).

        A tenant-scoped actor can only edit its own tenant's roles; the global
        built-ins are editable by a global ADMIN only.
        """
        require_permission(ctx, "role:manage")
        code = require(ctx.payload.get("role_code") or ctx.payload.get("code"), "role_code").upper()
        permissions = _validate_permissions(ctx, require(ctx.payload.get("permissions"), "permissions"))
        scope = _role_scope(ctx)
        row = db.execute(
            "UPDATE roles SET permissions = %s WHERE code = %s AND fiduciary_id IS NOT DISTINCT FROM %s::uuid",
            (db.as_jsonb(permissions), code, scope),
        )
        if row == 0:
            raise ApiError(404, "Not Found", f"Role '{code}' not found.")
        log_event(
            ctx.actor_email or "ADMIN",
            scope,
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
        scope = _role_scope(ctx)
        row = db.execute(
            "DELETE FROM roles WHERE code = %s AND fiduciary_id IS NOT DISTINCT FROM %s::uuid", (code, scope)
        )
        if row == 0:
            raise ApiError(404, "Not Found", f"Role '{code}' not found.")
        log_event(ctx.actor_email or "ADMIN", scope, "ADMIN_CONSOLE", None, "ROLE_DELETED", {"role_code": code})
        return {"success": True, "role_code": code}
