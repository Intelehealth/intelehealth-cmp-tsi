from __future__ import annotations

from dpdpcms_py.kernel import db
from dpdpcms_py.kernel.config import settings
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    require,
)


class PortalConfigHandlers:
    def set_rights_app_config(self, ctx: RequestContext) -> dict:
        otp_mode = str(require(ctx.payload.get("otp_mode"), "otp_mode")).upper()
        # SEC-14: DUMMY_OTP is a fixed, unauthenticated code. It is only ever
        # honoured where ALLOW_DUMMY_OTP permits; refusing to even record it in
        # other environments makes the evaluation mode impossible by accident.
        if otp_mode == "DUMMY_OTP" and not settings.allow_dummy_otp:
            raise ApiError(400, "Bad Request", "DUMMY_OTP is only available when ALLOW_DUMMY_OTP is enabled.")
        db.execute(
            """
            INSERT INTO rights_app_config (fiduciary_id, otp_mode, otp_message_template, pca_qr_enabled, last_updated_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (fiduciary_id) DO UPDATE SET
                otp_mode = EXCLUDED.otp_mode,
                otp_message_template = EXCLUDED.otp_message_template,
                pca_qr_enabled = EXCLUDED.pca_qr_enabled,
                last_updated_at = NOW()
            """,
            (
                require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),
                otp_mode,
                ctx.payload.get("otp_message_template"),
                bool(ctx.payload.get("pca_qr_enabled", True)),
            ),
        )
        return {"success": True}

    def get_rights_app_config(self, ctx: RequestContext) -> dict:
        row = db.one(
            "SELECT * FROM rights_app_config WHERE fiduciary_id = %s",
            (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),),
        )
        # SEC-14: no config row must never default to the evaluation mode. A
        # fiduciary that never configured the rights app now reads as EMAIL_OTP
        # (real delivery, fail-closed) instead of DUMMY_OTP (fixed code).
        return db.to_jsonable(
            row or {"fiduciary_id": ctx.payload.get("fiduciary_id"), "otp_mode": "EMAIL_OTP", "pca_qr_enabled": True}
        )
