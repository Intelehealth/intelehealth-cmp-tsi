from __future__ import annotations

from dpdpcms_py.kernel import db
from dpdpcms_py.kernel.context import ADMIN_FIDUCIARY_ID, RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import require
from dpdpcms_py.modules.administration.identity import authenticated_user_id
from dpdpcms_py.modules.audit_logging.ledger import log_event

# SA-06 / SEC-14: one PyJWKClient per configured JWKS URL, so each login does
# not re-fetch the provider's key set (fetching per call is both slow and a
# small denial-of-service surface). Keys rotate; the client re-fetches on a
# KeyError from PyJWT's get_signing_key_from_jwt.
MFA_MAX_FAILURES = 5


MFA_LOCKOUT_MINUTES = 15


class OperatorMfaHandlers:
    # ── TOTP MFA (SA-06) ─────────────────────────────────────────────
    def enrol_mfa(self, ctx: RequestContext) -> dict:
        """SA-06: generate a TOTP secret for the caller and return the provisioning URI.

        The secret is stored encrypted and shown exactly once; the account only
        becomes mfa_enabled after a successful verify_mfa round-trip.
        """
        from dpdpcms_py.modules.administration import totp

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
        from dpdpcms_py.kernel.security import token as issue_token
        from dpdpcms_py.modules.administration import totp

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
        # On first enrolment, sessions issued before MFA was on still carry mfa=true
        # (login grants it to accounts without MFA), so they are revoked here.
        db.execute(
            """
            UPDATE operators SET mfa_enabled = TRUE, mfa_verified_at = NOW(), last_updated_at = NOW(),
                   tokens_valid_after = CASE WHEN mfa_enabled THEN tokens_valid_after ELSE NOW() END
            WHERE id = %s
            """,
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
