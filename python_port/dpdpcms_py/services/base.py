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


def canonical_purpose_id(value: Any) -> str:
    """P10-04: the one spelling a purpose id is stored and compared under.

    Purpose ids are machine identifiers, so 'Marketing' and 'marketing' are the
    same purpose to the consent gate, the lifecycle, the retention clock and the
    legal hold alike. Canonicalising on write (and db/26 on the stored rows) is
    what keeps those four from disagreeing. 'ALL' is the whole-account sentinel
    and is left as written.
    """
    text = str(value if value is not None else "").strip()
    return text if text == "ALL" else text.lower()


# P10-01: the aliases a consent decision may name its purpose by, in the one
# order every reader uses - the same order as the SQL COALESCE in the erasure,
# closure and retention queries.
POINT_ID_KEYS = ("data_point_id", "purpose_id", "id")


def point_purpose_id(point: Any) -> str:
    """The canonical purpose id a stored consent decision names ('' if none)."""
    if not isinstance(point, dict):
        return ""
    for key in POINT_ID_KEYS:
        if point.get(key) not in (None, ""):
            return canonical_purpose_id(point[key])
    return ""


def canonical_consent_points(points: Any) -> Any:
    """P10-01: rewrite consent decisions onto data_point_id alone, canonical.

    A decision that names two DIFFERENT purposes through two aliases (e.g.
    {purpose_id: 'care', id: 'research'}) is refused: the declaration gate and
    the validator could otherwise read it as two different purposes. Anything
    that is not a list of objects is returned unchanged for the callers' own
    validation to reject.
    """
    if not isinstance(points, list):
        return points
    out: list[Any] = []
    for point in points:
        if not isinstance(point, dict):
            out.append(point)
            continue
        named = {canonical_purpose_id(point[k]) for k in POINT_ID_KEYS if point.get(k) not in (None, "")}
        if len(named) > 1:
            raise ApiError(
                400,
                "Bad Request",
                f"A consent decision names more than one purpose ({sorted(named)}); use data_point_id only.",
            )
        clean = {k: v for k, v in point.items() if k not in ("purpose_id", "id")}
        if named:
            clean["data_point_id"] = named.pop()
        out.append(clean)
    return out


def page_limit(payload: dict, default: int = 10) -> tuple[int, int]:
    page = max(1, int(payload.get("page") or 1))
    limit = min(500, max(1, int(payload.get("limit") or default)))
    return page, limit


def tenant_filter(ctx: RequestContext, column: str = "fiduciary_id") -> tuple[str, list[Any]]:
    """SQL fragment that confines a by-id query to the caller's tenant.

    Returns (" AND <column> = %s", [fid]) for any tenant-bound caller (API key,
    principal JWT, or a fiduciary-scoped operator) and ("", []) for a global
    administrator, so callers can append it to a WHERE clause unconditionally.
    """
    if ctx.fiduciary_id:
        return f" AND {column} = %s", [str(ctx.fiduciary_id)]
    return "", []


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
