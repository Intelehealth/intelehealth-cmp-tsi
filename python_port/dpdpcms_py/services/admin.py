from __future__ import annotations

from functools import lru_cache
from typing import Any

from .. import db, throttle
from ..audit import log_event
from ..context import ADMIN_FIDUCIARY_ID, RequestContext
from ..errors import ApiError
from ..security import hash_password, passphrase, token, verify_password
from .base import Service, require, tenant_filter

# SA-06 / SEC-14: one PyJWKClient per configured JWKS URL, so each login does
# not re-fetch the provider's key set (fetching per call is both slow and a
# small denial-of-service surface). Keys rotate; the client re-fetches on a
# KeyError from PyJWT's get_signing_key_from_jwt.
MFA_MAX_FAILURES = 5
MFA_LOCKOUT_MINUTES = 15


@lru_cache(maxsize=4)
def _jwks_client(jwks_url: str) -> Any:
    import jwt

    return jwt.PyJWKClient(jwks_url)


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
        return {
            "success": True,
            "message": "Super Administrator created successfully.",
            "data": {"user_id": str(row["id"]), "role": "ADMIN"},
        }


class OperatorService(Service):
    def login(self, ctx: RequestContext) -> dict:
        identifier = require(ctx.payload.get("identifier"), "identifier")
        password = require(ctx.payload.get("password"), "password")
        ip = ctx.source_ip or "unknown"
        # SEC-03: a password spray must be throttled at the account and the IP.
        # SEC-01/P5-03: the account key is the email HMAC, never the raw
        # identifier, so case/whitespace variants share one bucket and the
        # throttle table never stores addresses in clear.
        throttle.require_allowed("login:identifier", throttle.email_key(identifier))
        throttle.require_allowed("login:ip", ip)
        row = db.one(
            f"""
            SELECT o.id, o.name, {db.decrypt_col("o.email_enc")} AS email, o.password_hash,
                   o.status, o.role, o.fiduciary_id, f.name AS fiduciary_name
            FROM operators o LEFT JOIN fiduciaries f ON o.fiduciary_id = f.id
            WHERE o.name = %s OR o.email_hmac = {db.hmac_expr()}
            """,
            (*db.bind_key(), identifier, *db.bind_hmac(identifier)),
        )
        if not row or row["status"] != "ACTIVE" or not verify_password(password, row["password_hash"]):
            throttle.record_failure("login:identifier", throttle.email_key(identifier))
            throttle.record_failure("login:ip", ip)
            log_event(
                identifier,
                ADMIN_FIDUCIARY_ID,
                "ADMIN_CONSOLE",
                None,
                "LOGIN_FAILURE",
                "Invalid credentials or account inactive.",
                source_ip=ctx.source_ip,
            )
            raise ApiError(401, "Unauthorized", "Invalid credentials or account inactive.")
        # SEC-03: a successful login clears the throttle and writes the signal
        # a reviewer can spot from (last_login_at was never being written).
        throttle.record_success("login:identifier", throttle.email_key(identifier))
        throttle.record_success("login:ip", ip)
        db.execute("UPDATE operators SET last_login_at = NOW() WHERE id = %s", (row["id"],))
        fid = str(row["fiduciary_id"]) if row.get("fiduciary_id") else ADMIN_FIDUCIARY_ID
        mfa_row = db.one("SELECT mfa_enabled FROM operators WHERE id = %s", (row["id"],))
        mfa_enabled = bool(mfa_row and mfa_row["mfa_enabled"])
        # SA-06: when MFA is enabled, the password alone must not open the
        # console. Issue a token marked mfa:false that only verify_mfa can
        # upgrade to a full session.
        jwt_token = token(row["email"], row["name"], row["role"], extra={"mfa": not mfa_enabled})
        log_event(
            identifier,
            fid,
            "DPO_CONSOLE" if row["role"] == "DPO" else "ADMIN_CONSOLE",
            str(row["id"]),
            "LOGIN_SUCCESS",
            "Operator Access Granted",
            source_ip=ctx.source_ip,
        )
        out = {
            "success": True,
            "token": jwt_token,
            "role": row["role"],
            "username": row["name"],
            "fiduciary_id": fid,
            "mfa_required": mfa_enabled,
        }
        if row.get("fiduciary_name"):
            out["fiduciary_name"] = row["fiduciary_name"]
        return out

    def sso_login(self, ctx: RequestContext) -> dict:
        """SA-06: single sign-on through the organisation's OpenID Connect provider.

        The console completes the provider's login and posts the id_token here.
        It is verified against the provider's published keys (SSO_JWKS_URL), its
        issuer (SSO_ISSUER) and this CMS as audience (SSO_AUDIENCE); its email
        must belong to an ACTIVE operator. When the provider attests MFA (amr
        claim) the session is MFA-verified; otherwise an account with TOTP
        enrolled must still pass verify_mfa.
        """
        import jwt

        from ..config import settings

        if not (settings.sso_issuer and settings.sso_audience and settings.sso_jwks_url):
            raise ApiError(404, "Not Found", "Single sign-on is not configured.")
        raw = require(ctx.payload.get("id_token"), "id_token")
        nonce = ctx.payload.get("nonce")
        try:
            signing_key = _jwks_client(settings.sso_jwks_url).get_signing_key_from_jwt(raw)
            claims = jwt.decode(
                raw,
                signing_key.key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384"],
                audience=settings.sso_audience,
                issuer=settings.sso_issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
            )
        except Exception:
            log_event(
                "SSO",
                ADMIN_FIDUCIARY_ID,
                "ADMIN_CONSOLE",
                None,
                "LOGIN_FAILURE",
                "Invalid SSO token.",
                source_ip=ctx.source_ip,
            )
            raise ApiError(401, "Unauthorized", "Single sign-on failed.") from None
        # SEC-14: the id_token's nonce must be the one this deployment's console
        # sent with the authorize request, and it is single-use. A captured
        # token replayed with its original nonce loses the INSERT ... ON CONFLICT.
        if not nonce or str(nonce) != claims.get("nonce"):
            raise ApiError(401, "Unauthorized", "SSO nonce mismatch.")
        consumed = db.execute(
            "INSERT INTO sso_login_nonces (nonce, expires_at) VALUES (%s, NOW() + make_interval(mins => %s))"
            " ON CONFLICT (nonce) DO NOTHING",
            (str(nonce), settings.token_ttl_minutes),
        )
        if not consumed:
            raise ApiError(401, "Unauthorized", "SSO nonce has already been used.")
        email = claims.get("email")
        if not email or claims.get("email_verified") is False:
            raise ApiError(401, "Unauthorized", "The identity provider did not supply a verified email.")
        row = db.one(
            f"""
            SELECT o.id, o.name, o.role, o.fiduciary_id, o.mfa_enabled, f.name AS fiduciary_name
            FROM operators o LEFT JOIN fiduciaries f ON o.fiduciary_id = f.id
            WHERE o.email_hmac = {db.hmac_expr()} AND o.status = 'ACTIVE'
            """,
            db.bind_hmac(email),
        )
        if not row:
            log_event(
                email,
                ADMIN_FIDUCIARY_ID,
                "ADMIN_CONSOLE",
                None,
                "LOGIN_FAILURE",
                "SSO: no active operator.",
                source_ip=ctx.source_ip,
            )
            raise ApiError(401, "Unauthorized", "No active operator account matches this identity.")
        amr = {str(m).lower() for m in (claims.get("amr") or [])}
        idp_mfa = bool(amr & {"mfa", "otp", "hwk", "swk", "fido", "sms"})
        mfa_ok = idp_mfa or not row["mfa_enabled"]
        fid = str(row["fiduciary_id"]) if row.get("fiduciary_id") else ADMIN_FIDUCIARY_ID
        jwt_token = token(email, row["name"], row["role"], subject=str(row["id"]), extra={"mfa": mfa_ok, "sso": True})
        log_event(
            email,
            fid,
            "DPO_CONSOLE" if row["role"] == "DPO" else "ADMIN_CONSOLE",
            str(row["id"]),
            "LOGIN_SUCCESS",
            {"method": "SSO", "issuer": settings.sso_issuer, "idp_mfa": idp_mfa},
            source_ip=ctx.source_ip,
        )
        out = {
            "success": True,
            "token": jwt_token,
            "role": row["role"],
            "username": row["name"],
            "fiduciary_id": fid,
            "mfa_required": not mfa_ok,
        }
        if row.get("fiduciary_name"):
            out["fiduciary_name"] = row["fiduciary_name"]
        return out

    def logout(self, ctx: RequestContext) -> dict:
        """SA-05: revoke this session's token so it cannot be replayed until expiry."""
        token = ctx.auth_token or {}
        if token.get("jti") and token.get("exp"):
            db.execute(
                "INSERT INTO revoked_tokens (jti, expires_at) VALUES (%s, to_timestamp(%s)) ON CONFLICT (jti) DO NOTHING",
                (str(token["jti"]), int(token["exp"])),
            )
        return {"success": True, "message": "Logged out successfully."}

    # ── TOTP MFA (SA-06) ─────────────────────────────────────────────
    def enrol_mfa(self, ctx: RequestContext) -> dict:
        """SA-06: generate a TOTP secret for the caller and return the provisioning URI.

        The secret is stored encrypted and shown exactly once; the account only
        becomes mfa_enabled after a successful verify_mfa round-trip.
        """
        from .. import totp

        actor = authenticated_user_id(ctx)
        if not actor:
            raise ApiError(401, "Unauthorized", "You must be a signed-in operator to enrol MFA.")
        # Once MFA is enabled the enrolled secret is the second factor; letting a
        # password-only session replace it would let a stolen password enrol the
        # attacker's own authenticator.
        row = db.one("SELECT mfa_enabled FROM operators WHERE id = %s", (actor,))
        if row and row["mfa_enabled"]:
            if (ctx.auth_token or {}).get("mfa") is not True:
                raise ApiError(
                    403, "Forbidden", "MFA is enabled on this account. Verify with your current authenticator first."
                )
            raise ApiError(409, "Conflict", "MFA is already enabled on this account.")
        secret = totp.generate_secret()
        label = ctx.actor_email or ctx.actor_name or str(actor)
        updated = db.execute(
            f"""
            UPDATE operators SET mfa_secret_enc = {db.enc_expr()}, mfa_enabled = FALSE, mfa_enrolled_at = NOW(),
                   mfa_last_counter = NULL, mfa_failed_attempts = 0, mfa_locked_until = NULL, last_updated_at = NOW()
            WHERE id = %s AND mfa_enabled IS NOT TRUE
            """,
            (*db.bind_encrypt(secret), actor),
        )
        if updated == 0:
            raise ApiError(409, "Conflict", "MFA is already enabled on this account.")
        log_event(
            ctx.actor_email or "ADMIN",
            ADMIN_FIDUCIARY_ID,
            "ADMIN_CONSOLE",
            actor,
            "MFA_ENROLL_STARTED",
            "TOTP secret generated; verification pending.",
            source_ip=ctx.source_ip,
        )
        return {
            "success": True,
            "mfa": {
                "secret": secret,
                "otpauth_uri": totp.otpauth_uri(secret, label),
                "digits": totp.DIGITS,
                "period": totp.DEFAULT_STEP_SECONDS,
            },
            "message": "Scan this code in your authenticator app, then verify with verify_mfa.",
        }

    def verify_mfa(self, ctx: RequestContext) -> dict:
        """SA-06: confirm a TOTP code and, once verified, issue a session token that
        carries the mfa claim. The presenter must be the operator the secret belongs to."""
        from .. import totp
        from ..security import token as issue_token

        code = require(ctx.payload.get("code"), "code")
        # The secret verified is always the caller's own: a session can never name
        # another operator's account to test codes against.
        operator_id = authenticated_user_id(ctx)
        if not operator_id:
            raise ApiError(401, "Unauthorized", "You must be a signed-in operator to verify MFA.")
        # The secret is stored pgp-sym-encrypted as base64; the app key decrypts it.
        row = db.one(
            f"""
            SELECT id, name, {db.decrypt_col("email_enc")} AS email, status, role,
                   {db.decrypt_col("mfa_secret_enc")} AS secret,
                   COALESCE(mfa_locked_until > NOW(), FALSE) AS locked
            FROM operators WHERE id = %s
            """,
            (*db.bind_key(), *db.bind_key(), operator_id),
        )
        if not row or row["status"] != "ACTIVE":
            raise ApiError(401, "Unauthorized", "Operator not found or inactive.")
        stored_secret = row.get("secret")
        if not stored_secret:
            raise ApiError(400, "Bad Request", "No MFA secret is enrolled for this account.")
        if row["locked"]:
            raise ApiError(429, "Too Many Requests", "Too many invalid authenticator codes. Try again later.")
        counter = totp.match_counter(stored_secret, code)
        # A code is single-use: the stored counter only advances when the new one
        # is strictly greater, which rejects a replay atomically.
        accepted = counter is not None and (
            db.execute(
                """
                UPDATE operators SET mfa_last_counter = %s, mfa_failed_attempts = 0, mfa_locked_until = NULL
                WHERE id = %s AND (mfa_last_counter IS NULL OR mfa_last_counter < %s)
                """,
                (counter, operator_id, counter),
            )
            == 1
        )
        if not accepted:
            db.execute(
                """
                UPDATE operators SET mfa_failed_attempts = mfa_failed_attempts + 1,
                       mfa_locked_until = CASE WHEN mfa_failed_attempts + 1 >= %s
                                               THEN NOW() + make_interval(mins => %s) ELSE mfa_locked_until END
                WHERE id = %s
                """,
                (MFA_MAX_FAILURES, MFA_LOCKOUT_MINUTES, operator_id),
            )
            log_event(
                row["email"] or operator_id,
                ADMIN_FIDUCIARY_ID,
                "ADMIN_CONSOLE",
                str(row["id"]),
                "MFA_VERIFY_FAILED",
                {"reason": "Invalid, expired or already-used authenticator code."},
                source_ip=ctx.source_ip,
            )
            raise ApiError(401, "Unauthorized", "Invalid or expired authenticator code.")
        db.execute(
            "UPDATE operators SET mfa_enabled = TRUE, mfa_verified_at = NOW(), last_updated_at = NOW() WHERE id = %s",
            (operator_id,),
        )
        log_event(
            row["email"] or operator_id,
            ADMIN_FIDUCIARY_ID,
            "ADMIN_CONSOLE",
            str(row["id"]),
            "MFA_ENABLED",
            "TOTP verified; MFA now enforced on this account.",
            source_ip=ctx.source_ip,
        )
        jwt_token = issue_token(row["email"], row["name"], row["role"], subject=str(row["id"]), extra={"mfa": True})
        return {"success": True, "token": jwt_token, "mfa": True, "role": row["role"]}

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
            (username, email, *db.bind_encrypt(email), *db.bind_hmac(email), hash_password(password), role, fid),
        )
        log_event(
            email, fid or ADMIN_FIDUCIARY_ID, "ADMIN_CONSOLE", login_uid, "USER_CREATED", f"Role assigned: {role}"
        )
        return {"success": True, "user_id": str(row["id"])}

    def update_user(self, ctx: RequestContext) -> dict:
        uid = require(ctx.payload.get("user_id"), "user_id")
        fields = ["name = %s", "last_updated_at = NOW()"]
        params: list[Any] = [ctx.payload.get("username")]
        if ctx.payload.get("password"):
            # SA-05: a new password ends every existing session of the account.
            fields.append("password_hash = %s, tokens_valid_after = NOW()")
            params.append(hash_password(ctx.payload["password"]))
        if verified_role(ctx) == "ADMIN":
            fields.append("fiduciary_id = %s")
            params.append(ctx.payload.get("fiduciary_id") or None)
        scope, scope_params = tenant_filter(ctx)
        params.extend([uid, *scope_params])
        updated = db.execute(f"UPDATE operators SET {', '.join(fields)} WHERE id = %s AND role != 'ADMIN'{scope}", params)
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
            {"user_id": uid, "password_changed": bool(ctx.payload.get("password"))},
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

    def generate_recovery_key(self, ctx: RequestContext) -> dict:
        uid = require(ctx.payload.get("user_id"), "user_id")
        phrase = passphrase()
        # A recovery passphrase resets the target's password, so a tenant-scoped
        # caller may only mint one for a non-ADMIN operator in its own tenant.
        scope, scope_params = tenant_filter(ctx)
        if scope:
            scope += " AND role != 'ADMIN'"
        updated = db.execute(
            f"UPDATE operators SET recovery_key_hash = %s, last_updated_at = NOW() WHERE id = %s{scope}",
            (hash_password(phrase), uid, *scope_params),
        )
        if updated == 0:
            raise ApiError(404, "Not Found", "User not found.")
        return {"success": True, "passphrase": phrase}

    def verify_recovery_key(self, ctx: RequestContext) -> dict:
        email = require(ctx.payload.get("email"), "email")
        phrase = require(ctx.payload.get("passphrase"), "passphrase")
        ip = ctx.source_ip or "unknown"
        # SEC-01: the recovery passphrase is a bearer token; throttle both the
        # account and the source IP so it cannot be guessed or replayed, and
        # audit the attempt so a takeover leaves a trace. The account key is
        # the email HMAC (SEC-01/P5-03) so raw addresses never rest in
        # auth_throttles.key and normalisation variants share one bucket.
        throttle.require_allowed("recovery:email", throttle.email_key(email))
        throttle.require_allowed("recovery:ip", ip)
        row = db.one(
            f"SELECT recovery_key_hash FROM operators WHERE email_hmac = {db.hmac_expr()} AND status = 'ACTIVE'",
            db.bind_hmac(email),
        )
        if not row or not verify_password(phrase, row["recovery_key_hash"]):
            throttle.record_failure("recovery:email", throttle.email_key(email))
            throttle.record_failure("recovery:ip", ip)
            log_event(
                email,
                ADMIN_FIDUCIARY_ID,
                "ADMIN_CONSOLE",
                None,
                "RECOVERY_KEY_FAILURE",
                "Invalid recovery key.",
                source_ip=ctx.source_ip,
            )
            raise ApiError(401, "Unauthorized", "Invalid verification key.")
        throttle.record_success("recovery:email", throttle.email_key(email))
        throttle.record_success("recovery:ip", ip)
        log_event(
            email,
            ADMIN_FIDUCIARY_ID,
            "ADMIN_CONSOLE",
            None,
            "RECOVERY_KEY_VERIFIED",
            "Recovery key verified.",
            source_ip=ctx.source_ip,
        )
        return {"success": True}

    def reset_password_via_recovery(self, ctx: RequestContext) -> dict:
        self.verify_recovery_key(ctx)
        email = ctx.payload["email"]
        new_password = require(ctx.payload.get("new_password"), "new_password")
        # SEC-01: the same 12-character floor initial_setup enforces, so a
        # successful takeover cannot silently downgrade the account's password.
        if len(new_password) < 12:
            raise ApiError(400, "Bad Request", "Password must be at least 12 characters.")
        db.execute(
            f"UPDATE operators SET password_hash = %s, recovery_key_hash = NULL, tokens_valid_after = NOW(), last_login_at = NULL, last_updated_at = NOW() WHERE email_hmac = {db.hmac_expr()}",
            (hash_password(new_password), *db.bind_hmac(email)),
        )
        log_event(
            email,
            ADMIN_FIDUCIARY_ID,
            "ADMIN_CONSOLE",
            None,
            "PASSWORD_RESET_VIA_RECOVERY",
            "Password reset via recovery key.",
            source_ip=ctx.source_ip,
        )
        return {"success": True}


def _count(sql: str, params: tuple = ()) -> int:
    row = db.one(sql, params)
    return int(row["count"]) if row else 0


class AdminDashService(Service):
    def get_admin_metrics(self, ctx: RequestContext) -> dict:
        # SEC-06: the console reads data.metrics.<name>; keep the envelope and
        # names identical to AdminDash.java. dashboard:read is held by DPO,
        # OPERATOR and AUDITOR, so the counts are scoped to the caller's tenant
        # exactly like get_dpo_metrics; only a global ADMIN sees platform-wide
        # totals. A tenant-scoped caller gets its own fiduciary counted once.
        def masked(sql: str, column: str, params: tuple = ()) -> int:
            if ctx.fiduciary_id:
                sql += f" AND {column} = %s"
                params = (*params, str(ctx.fiduciary_id))
            return _count(sql, params)

        return {
            "success": True,
            "metrics": {
                "active_fiduciaries": masked(
                    "SELECT COUNT(*) AS count FROM fiduciaries WHERE status IN ('ACTIVE', 'PENDING')",
                    "id",
                ),
                "active_processors": masked(
                    "SELECT COUNT(*) AS count FROM apps WHERE status = 'ACTIVE'",
                    "fiduciary_id",
                ),
                "failed_purges": masked(
                    "SELECT COUNT(*) AS count FROM purge_requests WHERE status = 'FAILED'",
                    "fiduciary_id",
                ),
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
                "active_policies": _count(
                    "SELECT COUNT(*) AS count FROM consent_policies WHERE fiduciary_id = %s AND status = 'ACTIVE' AND created_at BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "total_consents": _count(
                    "SELECT COUNT(*) AS count FROM consent_records WHERE fiduciary_id = %s AND timestamp BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "data_principals": _count(
                    "SELECT COUNT(*) AS count FROM data_principal WHERE fiduciary_id = %s AND created_at BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "purge_total": _count(
                    "SELECT COUNT(*) AS count FROM purge_requests WHERE fiduciary_id = %s AND initiated_at BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "purge_pending": _count(
                    "SELECT COUNT(*) AS count FROM purge_requests WHERE fiduciary_id = %s AND status NOT IN ('PURGE_COMPLETED','LEGAL_HOLD_APPLIED') AND initiated_at BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "grievances_total": _count(
                    "SELECT COUNT(*) AS count FROM grievances WHERE fiduciary_id = %s AND submission_timestamp BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "grievances_pending": _count(
                    "SELECT COUNT(*) AS count FROM grievances WHERE fiduciary_id = %s AND status NOT IN ('RESOLVED') AND submission_timestamp BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "ropa_active": _count(
                    "SELECT COUNT(*) AS count FROM ropa_entries WHERE fiduciary_id = %s AND status = 'active' AND created_at BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "ropa_draft": _count(
                    "SELECT COUNT(*) AS count FROM ropa_entries WHERE fiduciary_id = %s AND status = 'draft' AND created_at BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
            },
        }

    def list_pending_grievances(self, ctx: RequestContext) -> list[dict]:
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        return db.to_jsonable(
            db.all(
                "SELECT * FROM grievances WHERE fiduciary_id = %s AND status IN ('NEW','IN_PROGRESS','ESCALATED') ORDER BY due_date ASC NULLS LAST LIMIT %s",
                (fid, int(ctx.payload.get("limit") or 10)),
            )
        )

    def list_access_logs(self, ctx: RequestContext) -> list[dict]:
        from .roles import require_audit_access

        require_audit_access(ctx)
        limit = int(ctx.payload.get("limit") or 10)
        scope, scope_params = tenant_filter(ctx)
        return db.to_jsonable(
            db.all(
                f"SELECT * FROM audit_logs WHERE 1 = 1{scope} ORDER BY timestamp DESC LIMIT %s",
                (*scope_params, limit),
            )
        )
