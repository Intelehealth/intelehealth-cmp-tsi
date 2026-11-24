from __future__ import annotations

from dpdpcms_py.kernel import db
from dpdpcms_py.kernel.context import RequestContext


def authenticated_user_id(ctx: RequestContext) -> str | None:
    if ctx.operator_id:
        return ctx.operator_id
    if not ctx.actor_email:
        return None
    row = db.one(
        f"SELECT id FROM operators WHERE email_hmac = {db.hmac_expr()} AND status = 'ACTIVE'",
        db.bind_hmac(ctx.actor_email),
    )
    return str(row["id"]) if row else None


def operator_fiduciary_id(operator_id: str | None) -> str | None:
    if not operator_id:
        return None
    row = db.one("SELECT fiduciary_id FROM operators WHERE id = %s", (operator_id,))
    return str(row["fiduciary_id"]) if row and row.get("fiduciary_id") else None
