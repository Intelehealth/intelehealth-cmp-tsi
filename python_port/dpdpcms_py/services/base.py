from __future__ import annotations

from typing import Any

from ..context import RequestContext
from ..errors import ApiError


class Service:
    def handle(self, ctx: RequestContext) -> Any:
        method = getattr(self, ctx.func, None)
        if not method or ctx.func.startswith("_"):
            raise ApiError(400, "Bad Request", f"Unsupported function: {ctx.func}")
        return method(ctx)


def require(value: Any, name: str) -> Any:
    if value is None or value == "":
        raise ApiError(400, "Bad Request", f"'{name}' is required.")
    return value


def page_limit(payload: dict, default: int = 10) -> tuple[int, int]:
    page = max(1, int(payload.get("page") or 1))
    limit = min(500, max(1, int(payload.get("limit") or default)))
    return page, limit


def reject_operator(ctx: RequestContext) -> None:
    if (ctx.actor_role or "").upper() == "OPERATOR":
        raise ApiError(403, "Forbidden", "Operators are not permitted to perform this action.")


def reject_principal(ctx: RequestContext, message: str = "This action is not permitted via a principal token.") -> None:
    if ctx.auth_via_principal_jwt:
        raise ApiError(403, "Forbidden", message)


def bind_principal_field(ctx: RequestContext, field: str) -> None:
    """Force a payload field to the authenticated principal when using a principal JWT."""
    if ctx.auth_via_principal_jwt and ctx.principal_user_id:
        supplied = ctx.payload.get(field)
        if supplied and str(supplied) != ctx.principal_user_id:
            raise ApiError(
                403,
                "Forbidden",
                f"{field} does not match the authenticated principal.",
            )
        ctx.payload[field] = ctx.principal_user_id


def ensure_principal_owns(
    ctx: RequestContext,
    owner_user_id: str | None,
    *,
    label: str = "Resource",
) -> None:
    """Block cross-principal access for principal JWT sessions (404 avoids ID leakage)."""
    if not ctx.auth_via_principal_jwt:
        return
    if owner_user_id is None or str(owner_user_id) != ctx.principal_user_id:
        raise ApiError(404, "Not Found", f"{label} not found.")


def principal_list_filter(ctx: RequestContext, field: str) -> str | None:
    """When called with a principal JWT, return the id that must be used to filter list queries."""
    if ctx.auth_via_principal_jwt:
        if not ctx.principal_user_id:
            raise ApiError(401, "Unauthorized", "Principal identity is missing from the token.")
        supplied = ctx.payload.get(field)
        if supplied and str(supplied) != ctx.principal_user_id:
            raise ApiError(
                403,
                "Forbidden",
                f"{field} does not match the authenticated principal.",
            )
        return ctx.principal_user_id
    return ctx.payload.get(field)
