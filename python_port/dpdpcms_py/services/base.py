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
