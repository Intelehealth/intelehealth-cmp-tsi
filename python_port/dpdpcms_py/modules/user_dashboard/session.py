from __future__ import annotations

from dpdpcms_py.kernel import db, pii, principal_otp, throttle
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.security import principal_token
from dpdpcms_py.kernel.service import (
    Service,
    require,
)
from dpdpcms_py.modules.audit_logging.ledger import log_event


class PrincipalService(Service):
    def list_active_fiduciaries(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(
            db.all(
                # otp_mode tells the rights portal whether to show "Send OTP".
                """
                SELECT f.id AS fiduciary_id, f.name, f.primary_domain, COALESCE(r.otp_mode, 'EMAIL_OTP') AS otp_mode
                FROM fiduciaries f LEFT JOIN rights_app_config r ON r.fiduciary_id = f.id
                WHERE f.status = 'ACTIVE' ORDER BY f.name
                """
            )
        )

    def list_fiduciary_personas(self, ctx: RequestContext) -> list[dict]:
        """Personas a principal can declare pre-login (Customer, Employee, Vendor...).

        Sourced from the data_subject_categories of the fiduciary's active ROPA
        entries. This is a public, unauthenticated endpoint -- it must never expose
        data_principal rows or any other personal data.
        """
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        return db.to_jsonable(
            db.all(
                """
            SELECT DISTINCT
                   lower(replace(trim(cat), ' ', '_')) AS id,
                   trim(cat)                           AS label
            FROM ropa_entries e,
                 LATERAL jsonb_array_elements_text(
                         CASE WHEN jsonb_typeof(e.data_subject_categories) = 'array'
                              THEN e.data_subject_categories ELSE '[]'::jsonb END) AS cat
            WHERE e.fiduciary_id = %s
              AND e.status = 'active'
              AND trim(cat) <> ''
            ORDER BY label
            LIMIT 100
            """,
                (fid,),
            )
        )

    @staticmethod
    def _otp_mode(fid: str) -> tuple[str, str | None]:
        """The fiduciary's configured OTP mode; 404 for an unknown or inactive fiduciary.

        SEC-14: an unconfigured fiduciary reads EMAIL_OTP (real delivery) rather
        than DUMMY_OTP; the fixed-code evaluation mode is only ever used when an
        operator expressly set it AND allow_dummy_otp permits it."""
        row = db.one(
            """
            SELECT COALESCE(r.otp_mode, 'EMAIL_OTP') AS otp_mode, r.otp_message_template
            FROM fiduciaries f LEFT JOIN rights_app_config r ON r.fiduciary_id = f.id
            WHERE f.id = %s AND f.status = 'ACTIVE'
            """,
            (fid,),
        )
        if not row:
            raise ApiError(404, "Not Found", "Fiduciary not found or inactive.")
        return str(row["otp_mode"]).upper(), row.get("otp_message_template")

    def request_principal_otp(self, ctx: RequestContext) -> dict:
        """Issue a one-time login code and send it to the principal out of band.

        The code is never returned in the response. Only its HMAC is stored, with
        an expiry; principal_login consumes it exactly once.
        """
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        user_id = pii.normalize(str(require(ctx.payload.get("user_id"), "user_id")))
        # P17-08: a locked principal or source IP cannot mint fresh codes either.
        self._otp_throttle_check(fid, user_id, ctx.source_ip)
        mode, template = self._otp_mode(fid)
        if mode == "DUMMY_OTP":
            if not principal_otp.dummy_allowed():
                raise ApiError(403, "Forbidden", "Evaluation OTP mode is disabled on this deployment.")
            return {"success": True, "message": "Evaluation mode: no OTP is sent."}
        subject = principal_otp.subject_key(fid, user_id)
        recent = db.one(
            "SELECT COUNT(*) AS count FROM principal_otps WHERE subject_hash = %s AND created_at > NOW() - make_interval(mins => %s)",
            (subject, principal_otp.REQUEST_WINDOW_MINUTES),
        )
        if recent and int(recent["count"]) >= principal_otp.MAX_REQUESTS_PER_WINDOW:
            raise ApiError(429, "Too Many Requests", "Too many OTP requests. Please wait and try again.")
        code = principal_otp.generate_code()
        with db.connection() as conn, conn.cursor() as cur:
            # Only the newest code is ever valid.
            cur.execute(
                "UPDATE principal_otps SET consumed_at = NOW() WHERE subject_hash = %s AND consumed_at IS NULL",
                (subject,),
            )
            cur.execute(
                """
                INSERT INTO principal_otps (fiduciary_id, subject_hash, code_hash, expires_at)
                VALUES (%s, %s, %s, NOW() + make_interval(mins => %s))
                """,
                (fid, subject, principal_otp.code_hash(subject, code), principal_otp.TTL_MINUTES),
            )
        # SEC-13: the code is encrypted at enqueue so webhook_deliveries.payload
        # never rests in the clear; the dispatcher decrypts it right before the
        # POST and the message template is rendered only at dispatch time.
        from dpdpcms_py.modules.notifications.api import queue_webhook

        enc_code = principal_otp.encrypt_code(code)
        message_template = template or "Your verification code is {{otp}}"
        queue_webhook(
            fid,
            "PRINCIPAL_OTP",
            {
                "channel": "EMAIL" if mode == "EMAIL_OTP" else "SMS",
                "recipient": user_id,
                "otp_enc": enc_code,
                "message_template": message_template,
                "expires_in_minutes": principal_otp.TTL_MINUTES,
            },
            category="OTP",
        )
        return {"success": True, "message": "OTP sent.", "expires_in_minutes": principal_otp.TTL_MINUTES}

    def principal_login(self, ctx: RequestContext) -> dict:
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        user_id = pii.normalize(str(require(ctx.payload.get("user_id"), "user_id")))
        supplied = str(require(ctx.payload.get("otp"), "otp")).strip()
        # P17-08: LoginRateLimiter semantics on the OTP login, per principal and per IP.
        self._otp_throttle_check(fid, user_id, ctx.source_ip)
        mode, _ = self._otp_mode(fid)
        if mode == "DUMMY_OTP":
            if not principal_otp.dummy_allowed() or not principal_otp.dummy_matches(supplied):
                self._otp_throttle_failure(fid, user_id, ctx.source_ip)
                raise ApiError(401, "Unauthorized", "Invalid OTP or account not found.")
        elif not self._consume_otp(fid, user_id, supplied):
            self._otp_throttle_failure(fid, user_id, ctx.source_ip)
            log_event(user_id, fid, "APP", None, "PRINCIPAL_LOGIN_FAILURE", {"reason": "Invalid or expired OTP."})
            raise ApiError(401, "Unauthorized", "Invalid OTP or account not found.")
        throttle.record_success(principal_otp.THROTTLE_SUBJECT_SCOPE, principal_otp.subject_key(fid, user_id))
        log_event(user_id, fid, "APP", None, "PRINCIPAL_LOGIN_SUCCESS", {"otp_mode": mode}, source_ip=ctx.source_ip)
        token = principal_token(fid, user_id)
        # UD-05: the rights portal builds its session from this response
        # (portal.js saveSession). Without the policies the Manage Consent tab
        # read "No active consent policy found" for every principal.
        persona = str(ctx.payload.get("persona") or "").strip()[:100] or None
        return {
            "success": True,
            "token": token,
            "user_id": user_id,
            "fiduciary_id": fid,
            **self._portal_session(fid),
            "persona": persona,
            "sync_token": token,
        }

    @staticmethod
    def _portal_session(fid: str) -> dict:
        """The fiduciary's name, its live policies (with the personas each is
        tagged for in the ROPA) and whether the PCA QR is enabled."""
        fiduciary = db.one(
            "SELECT f.name, r.pca_qr_enabled FROM fiduciaries f"
            " LEFT JOIN rights_app_config r ON r.fiduciary_id = f.id WHERE f.id = %s",
            (fid,),
        )
        rows = db.all(
            """
            SELECT DISTINCT ON (p.id) p.id AS policy_id, p.version, p.jurisdiction, p.policy_content,
                   COALESCE((
                       SELECT jsonb_agg(DISTINCT lower(replace(trim(cat), ' ', '_')))
                       FROM ropa_entries e, LATERAL jsonb_array_elements_text(
                         CASE WHEN jsonb_typeof(e.data_subject_categories) = 'array'
                              THEN e.data_subject_categories ELSE '[]'::jsonb END) AS cat
                       WHERE e.fiduciary_id = p.fiduciary_id AND e.linked_policy_ids @> jsonb_build_array(p.id)
                         AND e.status = 'active' AND trim(cat) <> ''
                   ), '[]'::jsonb) AS personas
            FROM consent_policies p
            WHERE p.fiduciary_id = %s AND p.status = 'ACTIVE' AND p.effective_date <= NOW()
            ORDER BY p.id, p.effective_date DESC
            """,
            (fid,),
        )
        policies = []
        for row in rows:
            content = row.get("policy_content") or {}
            block = (content.get("en") or next(iter(content.values()), {})) if isinstance(content, dict) else {}
            policies.append(
                {
                    "policy_id": row["policy_id"],
                    "version": row["version"],
                    "jurisdiction": row["jurisdiction"],
                    "title": (block.get("title") if isinstance(block, dict) else None) or row["policy_id"],
                    "personas": row.get("personas") or [],
                }
            )
        return {
            "fiduciary_name": (fiduciary or {}).get("name"),
            "policies": policies,
            "pca_qr_enabled": (fiduciary or {}).get("pca_qr_enabled") is not False,
        }

    @staticmethod
    def _otp_throttle_check(fid: str, user_id: str, source_ip: str | None) -> None:
        """P17-08: refuse (429) while the principal or the source IP is locked out."""
        throttle.require_allowed(principal_otp.THROTTLE_SUBJECT_SCOPE, principal_otp.subject_key(fid, user_id))
        throttle.require_allowed(principal_otp.THROTTLE_IP_SCOPE, source_ip or "unknown")

    @staticmethod
    def _otp_throttle_failure(fid: str, user_id: str, source_ip: str | None) -> None:
        """P17-08: count one failed OTP verification against the principal and the IP.

        The IP bucket is not cleared on success: one IP succeeding for its own
        principal must not wipe the record of it spraying codes at others."""
        throttle.record_failure(
            principal_otp.THROTTLE_SUBJECT_SCOPE,
            principal_otp.subject_key(fid, user_id),
            max_failures=principal_otp.MAX_SUBJECT_FAILURES,
        )
        throttle.record_failure(
            principal_otp.THROTTLE_IP_SCOPE, source_ip or "unknown", max_failures=principal_otp.MAX_IP_FAILURES
        )

    @staticmethod
    def _consume_otp(fid: str, user_id: str, supplied: str) -> bool:
        """Verify `supplied` against the live code; single-use, expiring, attempt-capped."""
        subject = principal_otp.subject_key(fid, user_id)
        row = db.one(
            """
            SELECT id, code_hash, attempts FROM principal_otps
            WHERE subject_hash = %s AND consumed_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC LIMIT 1
            """,
            (subject,),
        )
        if not row:
            return False
        if principal_otp.code_matches(subject, supplied, row["code_hash"]):
            # Consume atomically: a concurrent second login with the same code loses.
            return (
                db.execute(
                    "UPDATE principal_otps SET consumed_at = NOW() WHERE id = %s AND consumed_at IS NULL",
                    (row["id"],),
                )
                == 1
            )
        # A wrong guess burns an attempt; the code dies once the cap is reached.
        db.execute(
            """
            UPDATE principal_otps SET attempts = attempts + 1,
                   consumed_at = CASE WHEN attempts + 1 >= %s THEN NOW() ELSE consumed_at END
            WHERE id = %s
            """,
            (principal_otp.MAX_ATTEMPTS, row["id"]),
        )
        return False
