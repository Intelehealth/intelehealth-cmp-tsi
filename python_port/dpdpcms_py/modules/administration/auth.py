from __future__ import annotations

from functools import lru_cache
from typing import Any

from dpdpcms_py.kernel import db, throttle
from dpdpcms_py.kernel.context import ADMIN_FIDUCIARY_ID, RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.security import hash_password, passphrase, token, verify_password
from dpdpcms_py.kernel.service import require, tenant_filter
from dpdpcms_py.modules.audit_logging.ledger import log_event


@lru_cache(maxsize=4)
def _jwks_client(jwks_url: str) -> Any:
    import jwt

    return jwt.PyJWKClient(jwks_url)


class OperatorAuthHandlers:
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
        from dpdpcms_py.kernel.config import settings

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
