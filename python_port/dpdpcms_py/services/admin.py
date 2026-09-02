from __future__ import annotations

from typing import Any

from .. import db
from ..audit import log_event
from ..context import ADMIN_FIDUCIARY_ID, RequestContext
from ..errors import ApiError
from ..security import hash_password, passphrase, token, verify_password
from .base import Service, page_limit, require


def authenticated_user_id(ctx: RequestContext) -> str | None:
    if not ctx.actor_email:
        return None
    row = db.one(
        f"SELECT id FROM operators WHERE email_hmac = {db.hmac_expr()} AND status = 'ACTIVE'",
        db.bind_hmac(ctx.actor_email),
    )
    return str(row["id"]) if row else None


def verified_role(ctx: RequestContext) -> str | None:
    if not ctx.actor_email:
        return None
    row = db.one(
        f"SELECT role FROM operators WHERE email_hmac = {db.hmac_expr()} AND status = 'ACTIVE'",
        db.bind_hmac(ctx.actor_email),
    )
    return row["role"] if row else None


def operator_fiduciary_id(operator_id: str | None) -> str | None:
    if not operator_id:
        return None
    row = db.one("SELECT fiduciary_id FROM operators WHERE id = %s", (operator_id,))
    return str(row["fiduciary_id"]) if row and row.get("fiduciary_id") else None


class AdminSetupService(Service):
    def initial_setup(self, ctx: RequestContext) -> dict:
        payload = ctx.payload
        email = require(payload.get("email"), "email")
        name = require(payload.get("name"), "name")
        password = require(payload.get("password"), "password")
        if len(password) < 12:
            raise ApiError(400, "Bad Request", "Password must be at least 12 characters.")
        existing = db.one("SELECT COUNT(*) AS count FROM operators WHERE role = 'ADMIN'")
        if existing and existing["count"] > 0:
            raise ApiError(409, "Setup Failure", "System is already configured. Cannot run initial setup.")
        row = db.insert_returning(
            f"""
            INSERT INTO operators
                (id, name, email_plaintext, email_enc, email_hmac, password_hash, status, role, created_at, last_updated_at)
            VALUES (uuid_generate_v4(), %s, %s, {db.enc_expr()}, {db.hmac_expr()}, %s, 'ACTIVE', 'ADMIN', NOW(), NOW())
            RETURNING id
            """,
            (name, email, *db.bind_encrypt(email), *db.bind_hmac(email), hash_password(password)),
        )
        return {"success": True, "message": "Super Administrator created successfully.", "data": {"user_id": str(row["id"]), "role": "ADMIN"}}


class OperatorService(Service):
    def login(self, ctx: RequestContext) -> dict:
        identifier = require(ctx.payload.get("identifier"), "identifier")
        password = require(ctx.payload.get("password"), "password")
        row = db.one(
            f"""
            SELECT o.id, o.name, {db.decrypt_col('o.email_enc')} AS email, o.password_hash,
                   o.status, o.role, o.fiduciary_id, f.name AS fiduciary_name
            FROM operators o LEFT JOIN fiduciaries f ON o.fiduciary_id = f.id
            WHERE o.name = %s OR o.email_hmac = {db.hmac_expr()}
            """,
            (*db.bind_key(), identifier, *db.bind_hmac(identifier)),
        )
        if not row or row["status"] != "ACTIVE" or not verify_password(password, row["password_hash"]):
            log_event(identifier, ADMIN_FIDUCIARY_ID, "ADMIN_CONSOLE", None, "LOGIN_FAILURE", "Invalid credentials or account inactive.")
            raise ApiError(401, "Unauthorized", "Invalid credentials or account inactive.")
        fid = str(row["fiduciary_id"]) if row.get("fiduciary_id") else ADMIN_FIDUCIARY_ID
        jwt_token = token(row["email"], row["name"], row["role"])
        log_event(identifier, fid, "DPO_CONSOLE" if row["role"] == "DPO" else "ADMIN_CONSOLE", str(row["id"]), "LOGIN_SUCCESS", "Operator Access Granted")
        out = {"success": True, "token": jwt_token, "role": row["role"], "username": row["name"], "fiduciary_id": fid}
        if row.get("fiduciary_name"):
            out["fiduciary_name"] = row["fiduciary_name"]
        return out

    def logout(self, ctx: RequestContext) -> dict:
        return {"success": True, "message": "Logged out successfully."}

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
            where.append("(u.name ILIKE %s OR u.email_plaintext ILIKE %s)")
            params.extend([f"%{search}%", f"%{search}%"])
        sql_where = "WHERE " + " AND ".join(where) if where else ""
        return db.to_jsonable(db.all(
            f"""
            SELECT u.id AS user_id, u.name AS username, {db.decrypt_col('u.email_enc')} AS email,
                   u.status, u.role, u.fiduciary_id, f.name AS fiduciary_name
            FROM operators u LEFT JOIN fiduciaries f ON u.fiduciary_id = f.id
            {sql_where}
            ORDER BY u.created_at DESC
            """,
            params,
        ))

    def get_user(self, ctx: RequestContext) -> dict:
        uid = require(ctx.payload.get("user_id"), "user_id")
        row = db.one(
            f"SELECT id AS user_id, name AS username, {db.decrypt_col('email_enc')} AS email, fiduciary_id, role AS role_name FROM operators WHERE id = %s",
            (*db.bind_key(), uid),
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
        fid = payload.get("fiduciary_id") or None
        login_uid = authenticated_user_id(ctx)
        if caller_role == "DPO":
            if role != "OPERATOR":
                raise ApiError(403, "Forbidden", "DPO users may only create OPERATOR accounts.")
            fid = operator_fiduciary_id(login_uid)
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
            (username, email, *db.bind_encrypt(email), *db.bind_hmac(email), hash_password(password), role, fid),
        )
        log_event(email, fid or ADMIN_FIDUCIARY_ID, "ADMIN_CONSOLE", login_uid, "USER_CREATED", f"Role assigned: {role}")
        return {"success": True, "user_id": str(row["id"])}

    def update_user(self, ctx: RequestContext) -> dict:
        uid = require(ctx.payload.get("user_id"), "user_id")
        fields = ["name = %s", "last_updated_at = NOW()"]
        params: list[Any] = [ctx.payload.get("username")]
        if ctx.payload.get("password"):
            fields.append("password_hash = %s")
            params.append(hash_password(ctx.payload["password"]))
        if verified_role(ctx) == "ADMIN":
            fields.append("fiduciary_id = %s")
            params.append(ctx.payload.get("fiduciary_id") or None)
        params.append(uid)
        db.execute(f"UPDATE operators SET {', '.join(fields)} WHERE id = %s AND role != 'ADMIN'", params)
        return {"success": True, "message": "User updated successfully."}

    def deactivate_user(self, ctx: RequestContext) -> dict:
        uid = require(ctx.payload.get("user_id"), "user_id")
        db.execute("UPDATE operators SET status = 'INACTIVE', last_updated_at = NOW() WHERE id = %s AND role != 'ADMIN'", (uid,))
        return {"success": True}

    def generate_recovery_key(self, ctx: RequestContext) -> dict:
        uid = require(ctx.payload.get("user_id"), "user_id")
        phrase = passphrase()
        db.execute("UPDATE operators SET recovery_key_hash = %s, last_updated_at = NOW() WHERE id = %s", (hash_password(phrase), uid))
        return {"success": True, "passphrase": phrase}

    def verify_recovery_key(self, ctx: RequestContext) -> dict:
        email = require(ctx.payload.get("email"), "email")
        phrase = require(ctx.payload.get("passphrase"), "passphrase")
        row = db.one(f"SELECT recovery_key_hash FROM operators WHERE email_hmac = {db.hmac_expr()} AND status = 'ACTIVE'", db.bind_hmac(email))
        if not row or not verify_password(phrase, row["recovery_key_hash"]):
            raise ApiError(401, "Unauthorized", "Invalid verification key.")
        return {"success": True}

    def reset_password_via_recovery(self, ctx: RequestContext) -> dict:
        self.verify_recovery_key(ctx)
        email = ctx.payload["email"]
        db.execute(
            f"UPDATE operators SET password_hash = %s, recovery_key_hash = NULL, last_updated_at = NOW() WHERE email_hmac = {db.hmac_expr()}",
            (hash_password(require(ctx.payload.get("new_password"), "new_password")), *db.bind_hmac(email)),
        )
        return {"success": True}


def _count(sql: str, params: tuple = ()) -> int:
    row = db.one(sql, params)
    return int(row["count"]) if row else 0


class AdminDashService(Service):
    def get_admin_metrics(self, ctx: RequestContext) -> dict:
        # The console reads data.metrics.<name>; keep the envelope and names identical to AdminDash.java.
        return {
            "success": True,
            "metrics": {
                "active_fiduciaries": _count("SELECT COUNT(*) AS count FROM fiduciaries WHERE status IN ('ACTIVE', 'PENDING')"),
                "active_processors": _count("SELECT COUNT(*) AS count FROM apps WHERE status = 'ACTIVE'"),
                "failed_purges": _count("SELECT COUNT(*) AS count FROM purge_requests WHERE status = 'FAILED'"),
            },
        }

    def get_dpo_metrics(self, ctx: RequestContext) -> dict:
        fid = ctx.payload.get("fiduciary_id") or ctx.fiduciary_id or operator_fiduciary_id(authenticated_user_id(ctx))
        start = ctx.payload.get("start_date") or "1970-01-01"
        end = ctx.payload.get("end_date") or "9999-12-31"
        window = (fid, start, end)
        return {
            "success": True,
            "metrics": {
                "active_policies": _count("SELECT COUNT(*) AS count FROM consent_policies WHERE fiduciary_id = %s AND status = 'ACTIVE' AND created_at BETWEEN %s::timestamp AND %s::timestamp", window),
                "total_consents": _count("SELECT COUNT(*) AS count FROM consent_records WHERE fiduciary_id = %s AND timestamp BETWEEN %s::timestamp AND %s::timestamp", window),
                "data_principals": _count("SELECT COUNT(*) AS count FROM data_principal WHERE fiduciary_id = %s AND created_at BETWEEN %s::timestamp AND %s::timestamp", window),
                "purge_total": _count("SELECT COUNT(*) AS count FROM purge_requests WHERE fiduciary_id = %s AND initiated_at BETWEEN %s::timestamp AND %s::timestamp", window),
                "purge_pending": _count("SELECT COUNT(*) AS count FROM purge_requests WHERE fiduciary_id = %s AND status NOT IN ('PURGE_COMPLETED','LEGAL_HOLD_APPLIED') AND initiated_at BETWEEN %s::timestamp AND %s::timestamp", window),
                "grievances_total": _count("SELECT COUNT(*) AS count FROM grievances WHERE fiduciary_id = %s AND submission_timestamp BETWEEN %s::timestamp AND %s::timestamp", window),
                "grievances_pending": _count("SELECT COUNT(*) AS count FROM grievances WHERE fiduciary_id = %s AND status NOT IN ('RESOLVED') AND submission_timestamp BETWEEN %s::timestamp AND %s::timestamp", window),
                "ropa_active": _count("SELECT COUNT(*) AS count FROM ropa_entries WHERE fiduciary_id = %s AND status = 'active' AND created_at BETWEEN %s::timestamp AND %s::timestamp", window),
                "ropa_draft": _count("SELECT COUNT(*) AS count FROM ropa_entries WHERE fiduciary_id = %s AND status = 'draft' AND created_at BETWEEN %s::timestamp AND %s::timestamp", window),
            },
        }

    def list_pending_grievances(self, ctx: RequestContext) -> list[dict]:
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        return db.to_jsonable(db.all("SELECT * FROM grievances WHERE fiduciary_id = %s AND status IN ('NEW','IN_PROGRESS','ESCALATED') ORDER BY due_date ASC NULLS LAST LIMIT %s", (fid, int(ctx.payload.get("limit") or 10))))

    def list_access_logs(self, ctx: RequestContext) -> list[dict]:
        limit = int(ctx.payload.get("limit") or 10)
        return db.to_jsonable(db.all("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT %s", (limit,)))
