from __future__ import annotations

from dpdpcms_py.kernel import db
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.security import hash_password
from dpdpcms_py.kernel.service import Service, require


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
            # R6-a: email_plaintext is no longer written; email_enc is the copy.
            (name, None, *db.bind_encrypt(email), *db.bind_hmac(email), hash_password(password)),
        )
        return {
            "success": True,
            "message": "Super Administrator created successfully.",
            "data": {"user_id": str(row["id"]), "role": "ADMIN"},
        }
