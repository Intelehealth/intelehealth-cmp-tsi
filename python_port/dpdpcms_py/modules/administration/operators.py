from __future__ import annotations

from typing import Any

from dpdpcms_py.kernel import db
from dpdpcms_py.kernel.context import ADMIN_FIDUCIARY_ID, RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.security import hash_password
from dpdpcms_py.kernel.service import Service, require, tenant_filter
from dpdpcms_py.modules.administration.auth import OperatorAuthHandlers
from dpdpcms_py.modules.administration.identity import authenticated_user_id, operator_fiduciary_id
from dpdpcms_py.modules.administration.mfa import OperatorMfaHandlers
from dpdpcms_py.modules.audit_logging.ledger import log_event


def verified_role(ctx: RequestContext) -> str | None:
    if not ctx.actor_email:
        return None
    row = db.one(
        f"SELECT role FROM operators WHERE email_hmac = {db.hmac_expr()} AND status = 'ACTIVE'",
        db.bind_hmac(ctx.actor_email),
    )
    return row["role"] if row else None


class OperatorService(OperatorAuthHandlers, OperatorMfaHandlers, Service):
    def list_users(self, ctx: RequestContext) -> list[dict]:
        role = verified_role(ctx)
        uid = authenticated_user_id(ctx)
        params: list[Any] = [*db.bind_key()]
        where = []
        if role != "ADMIN":
            where.append("u.fiduciary_id = (SELECT fiduciary_id FROM operators WHERE id = %s)")
            params.append(uid)
        search = ctx.payload.get("search")
        if search:
            # R6-a: the email is searched in its decrypted form, never a plaintext column.
            where.append(f"(u.name ILIKE %s OR {db.decrypt_col('u.email_enc')} ILIKE %s)")
            params.extend([f"%{search}%", *db.bind_key(), f"%{search}%"])
        sql_where = "WHERE " + " AND ".join(where) if where else ""
        return db.to_jsonable(
            db.all(
                f"""
            SELECT u.id AS user_id, u.name AS username, {db.decrypt_col("u.email_enc")} AS email,
                   u.status, u.role, u.fiduciary_id, f.name AS fiduciary_name
            FROM operators u LEFT JOIN fiduciaries f ON u.fiduciary_id = f.id
            {sql_where}
            ORDER BY u.created_at DESC
            """,
                params,
            )
        )

    def get_user(self, ctx: RequestContext) -> dict:
        uid = require(ctx.payload.get("user_id"), "user_id")
        scope, scope_params = tenant_filter(ctx)
        row = db.one(
            f"SELECT id AS user_id, name AS username, {db.decrypt_col('email_enc')} AS email, fiduciary_id, role AS role_name FROM operators WHERE id = %s{scope}",
            (*db.bind_key(), uid, *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "User not found.")
        return db.to_jsonable(row)

    def create_user(self, ctx: RequestContext) -> dict:
        payload = ctx.payload
        caller_role = verified_role(ctx)
        role = require(payload.get("role"), "role").upper()
        if role == "ADMIN" and caller_role != "ADMIN":
            raise ApiError(403, "Forbidden", "Only ADMIN users may assign the ADMIN role.")
        # SA-01 / SA-02: every role must exist in the roles table (built-in or
        # custom); a DPO may create OPERATOR or custom read roles but not manage
        # ADMIN or AUDITOR assignments.
        known = db.one(
            "SELECT 1 FROM roles WHERE code = %s AND (fiduciary_id IS NULL OR fiduciary_id = %s::uuid)",
            (role, ctx.fiduciary_id or payload.get("fiduciary_id") or None),
        )
        if not known:
            raise ApiError(400, "Bad Request", f"Unknown role '{role}'. See list_roles.")
        login_uid = authenticated_user_id(ctx)
        if caller_role == "DPO":
            if role != "OPERATOR":
                raise ApiError(403, "Forbidden", "DPO users may only create OPERATOR accounts.")
            fid = operator_fiduciary_id(login_uid)
        else:
            fid = payload.get("fiduciary_id") or None
        # P10-03: the new account's role may carry no permission the caller lacks.
        from dpdpcms_py.modules.administration.roles import ensure_role_assignable

        ensure_role_assignable(ctx, role, ctx.fiduciary_id or fid)
        # SEC-18: a non-ADMIN operator with a NULL fiduciary_id defeats every
        # tenancy check in the system, so that account shape is refused at
        # creation instead of patching each caller. Only a global ADMIN may hold
        # no tenant. This also means the reverse: any tenant-scoped caller is
        # guaranteed a fiduciary_id below.
        if role != "ADMIN" and not fid:
            raise ApiError(400, "Bad Request", "Non-ADMIN operators must belong to a fiduciary_id.")
        username = require(payload.get("username"), "username")
        email = require(payload.get("email"), "email")
        password = require(payload.get("password"), "password")
        row = db.insert_returning(
            f"""
            INSERT INTO operators
                (id, name, email_plaintext, email_enc, email_hmac, password_hash, role, status, fiduciary_id, created_at, last_updated_at)
            VALUES (uuid_generate_v4(), %s, %s, {db.enc_expr()}, {db.hmac_expr()}, %s, %s, 'ACTIVE', %s, NOW(), NOW())
            RETURNING id
            """,
            (username, None, *db.bind_encrypt(email), *db.bind_hmac(email), hash_password(password), role, fid),
        )
        log_event(
            email, fid or ADMIN_FIDUCIARY_ID, "ADMIN_CONSOLE", login_uid, "USER_CREATED", f"Role assigned: {role}"
        )
        return {"success": True, "user_id": str(row["id"])}

    def update_user(self, ctx: RequestContext) -> dict:
        uid = require(ctx.payload.get("user_id"), "user_id")
        fields = ["last_updated_at = NOW()"]
        params: list[Any] = []
        # SA-04: name only changes when one is supplied; the column is NOT NULL.
        if "username" in ctx.payload:
            username = str(ctx.payload.get("username") or "").strip()
            if not username:
                raise ApiError(400, "Bad Request", "username must not be empty.")
            fields.append("name = %s")
            params.append(username)
        # SA-04: role assignment follows the same rules as create_user.
        new_role = None
        end_sessions = False
        if ctx.payload.get("role"):
            new_role = str(ctx.payload["role"]).upper()
            caller_role = verified_role(ctx)
            if new_role == "ADMIN" and caller_role != "ADMIN":
                raise ApiError(403, "Forbidden", "Only ADMIN users may assign the ADMIN role.")
            if caller_role == "DPO" and new_role != "OPERATOR":
                raise ApiError(403, "Forbidden", "DPO users may only assign the OPERATOR role.")
            target = db.one("SELECT fiduciary_id, role FROM operators WHERE id = %s", (uid,))
            if caller_role == "DPO" and target and str(target.get("role") or "").upper() != "OPERATOR":
                raise ApiError(403, "Forbidden", "DPO users may only change the role of OPERATOR accounts.")
            # P10-03: no operator changes its own role - promotion is always
            # someone else's decision - and the role assigned may carry no
            # permission the caller does not itself hold.
            if str(uid) == str(authenticated_user_id(ctx) or ""):
                raise ApiError(403, "Forbidden", "Operators cannot change their own role.")
            role_fid = ctx.fiduciary_id or ctx.payload.get("fiduciary_id") or (target or {}).get("fiduciary_id")
            from dpdpcms_py.modules.administration.roles import ensure_role_assignable

            ensure_role_assignable(ctx, new_role, str(role_fid) if role_fid else None)
            # A role change takes effect on the next request; end old sessions too.
            fields.append("role = %s")
            params.append(new_role)
            end_sessions = True
        new_status = None
        if ctx.payload.get("status"):
            new_status = str(ctx.payload["status"]).upper()
            if new_status not in {"ACTIVE", "INACTIVE"}:
                raise ApiError(400, "Bad Request", "status must be ACTIVE or INACTIVE.")
            fields.append("status = %s")
            params.append(new_status)
            end_sessions = end_sessions or new_status == "INACTIVE"
        if ctx.payload.get("password"):
            # SA-05: a new password ends every existing session of the account.
            fields.append("password_hash = %s")
            params.append(hash_password(ctx.payload["password"]))
            end_sessions = True
        if end_sessions:
            fields.append("tokens_valid_after = NOW()")
        # SEC-18: the WHERE below targets exactly non-ADMIN rows, so a NULL
        # fiduciary_id on these rows is the account shape that defeats every
        # tenancy check. The field is updated ONLY when the caller explicitly
        # supplies it — an ADMIN rename that omits it must not silently null the
        # operator's tenant — and a NULL value is refused outright.
        if "fiduciary_id" in ctx.payload:
            new_fid = ctx.payload.get("fiduciary_id") or None
            if not new_fid:
                raise ApiError(400, "Bad Request", "Non-ADMIN operators must belong to a fiduciary_id.")
            # A tenant-scoped caller cannot hand its operator to another tenant.
            if ctx.fiduciary_id and str(new_fid).lower() != str(ctx.fiduciary_id).lower():
                raise ApiError(403, "Forbidden", "Operators cannot be moved to another fiduciary.")
            fields.append("fiduciary_id = %s")
            params.append(new_fid)
        scope, scope_params = tenant_filter(ctx)
        params.extend([uid, *scope_params])
        updated = db.execute(
            f"UPDATE operators SET {', '.join(fields)} WHERE id = %s AND role != 'ADMIN'{scope}", params
        )
        # SEC-12: an update that did not happen (unknown id, ADMIN target, or a
        # cross-tenant id) is not logged or reported as done.
        if updated == 0:
            raise ApiError(404, "Not Found", "User not found.")
        log_event(
            ctx.actor_email or "ADMIN",
            ctx.fiduciary_id or ADMIN_FIDUCIARY_ID,
            "ADMIN_CONSOLE",
            authenticated_user_id(ctx),
            "USER_UPDATED",
            {
                "user_id": uid,
                "password_changed": bool(ctx.payload.get("password")),
                "role": new_role,
                "status": new_status,
            },
            source_ip=ctx.source_ip,
        )
        return {"success": True, "message": "User updated successfully."}

    def deactivate_user(self, ctx: RequestContext) -> dict:
        uid = require(ctx.payload.get("user_id"), "user_id")
        scope, scope_params = tenant_filter(ctx)
        updated = db.execute(
            f"UPDATE operators SET status = 'INACTIVE', tokens_valid_after = NOW(), last_updated_at = NOW() WHERE id = %s AND role != 'ADMIN'{scope}",
            (uid, *scope_params),
        )
        # SEC-12: a deactivation that did not happen is not logged as done.
        if updated == 0:
            raise ApiError(404, "Not Found", "User not found.")
        log_event(
            ctx.actor_email or "ADMIN",
            ctx.fiduciary_id or ADMIN_FIDUCIARY_ID,
            "ADMIN_CONSOLE",
            authenticated_user_id(ctx),
            "USER_DEACTIVATED",
            {"user_id": uid},
            source_ip=ctx.source_ip,
        )
        return {"success": True}
