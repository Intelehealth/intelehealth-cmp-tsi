from __future__ import annotations

import json

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    bind_principal_field,
    require,
)
from dpdpcms_py.modules.audit_logging.ledger import log_event
from dpdpcms_py.modules.consent_lifecycle.common import _USER_MATCH, _console_record, _fid, _require_console_operator

# CC-05: how a guardian's identity may be established. Only EXISTING_ACCOUNT and
# DIGILOCKER can reach VERIFIED; the rest are recorded as assertions.
GUARDIAN_MECHANISMS = {"EXISTING_ACCOUNT", "DIGILOCKER", "AADHAAR_VC", "KYC_PROVIDER", "OTP_LINKING"}


def _verify_with_digilocker(fiduciary_id: str, guardian_id: str, ref_id: str) -> tuple[str, str | None]:
    """Confirm a DigiLocker reference through the configured verifier service.

    The verifier is the deployment's DigiLocker partner integration. It receives
    the reference and answers {"verified": bool, "is_adult": bool}. With no
    verifier configured the log stays PENDING and cannot back a minor's consent.
    """
    from dpdpcms_py.kernel.config import settings
    from dpdpcms_py.kernel.netutil import post_json

    if not settings.digilocker_verify_url:
        return "PENDING", "No DigiLocker verifier is configured (DIGILOCKER_VERIFY_URL)."
    try:
        status, body = post_json(
            settings.digilocker_verify_url,
            {"fiduciary_id": fiduciary_id, "guardian_principal_id": guardian_id, "verification_ref_id": ref_id},
            timeout=15,
        )
    except ValueError as exc:
        return "PENDING", str(exc)
    if status is None or status >= 400:
        return "PENDING", f"DigiLocker verifier unavailable ({status})."
    try:
        answer = json.loads(body or "{}")
    except ValueError:
        return "PENDING", "DigiLocker verifier returned an unreadable response."
    if answer.get("verified") is True and answer.get("is_adult") is True:
        return "VERIFIED", None
    return "REJECTED", "DigiLocker did not confirm an adult guardian for this reference."


def _has_proof_metadata(proof: str | None) -> bool:
    """Whether the guardian log holds caller-supplied proof, beyond the server's own verification_detail."""
    if not proof:
        return False
    try:
        value = json.loads(proof)
    except ValueError:
        return True
    if isinstance(value, dict):
        return any(v not in (None, "", {}, []) for k, v in value.items() if k != "verification_detail")
    return value not in (None, "", {}, [])


def _verification_detail(proof: str | None) -> str | None:
    """The server-written verification_detail record_parent_consent stores beside the proof."""
    try:
        value = json.loads(proof) if proof else None
    except ValueError:
        return None
    return value.get("verification_detail") if isinstance(value, dict) else None


class GuardianHandlers:
    def record_parent_consent(self, ctx: RequestContext) -> dict:
        """CC-05: record a guardian verification, verifying it where the CMS can.

        EXISTING_ACCOUNT is verified here: the guardian must already be a known
        ADULT principal of this fiduciary. DIGILOCKER is verified by the
        configured verifier (DIGILOCKER_VERIFY_URL), which must confirm the
        reference and that the guardian is an adult. Anything else is stored as
        an unverified assertion and cannot back a minor's consent.
        """
        payload = ctx.payload
        bind_principal_field(ctx, "guardian_principal_id")
        fid = _fid(ctx)
        child = require(payload.get("child_principal_id"), "child_principal_id")
        guardian = require(payload.get("guardian_principal_id"), "guardian_principal_id")
        mechanism = str(require(payload.get("verification_mechanism"), "verification_mechanism")).upper()
        if mechanism not in GUARDIAN_MECHANISMS:
            raise ApiError(400, "Bad Request", f"verification_mechanism must be one of {sorted(GUARDIAN_MECHANISMS)}.")
        if pii.normalize(str(guardian)) == pii.normalize(str(child)):
            raise ApiError(400, "Bad Request", "A principal cannot act as their own guardian.")
        ref_id = payload.get("verification_ref_id")
        status, detail = "ASSERTED", "Recorded as an assertion; only EXISTING_ACCOUNT or DIGILOCKER can verify."
        if mechanism == "EXISTING_ACCOUNT":
            # SEC-05: guardianship is proven by a row the server recorded as
            # ADULT, never by the column default. A principal whose age the CMS
            # has not attested (NULL) cannot vouch for a minor.
            adult = db.one(
                f"SELECT 1 FROM data_principal WHERE {_USER_MATCH} AND fiduciary_id = %s AND age_category = 'ADULT'",
                (*pii.hmac_params(guardian), fid),
            )
            status = "VERIFIED" if adult else "REJECTED"
            detail = None if adult else "Guardian has no adult account with this fiduciary."
        elif mechanism == "DIGILOCKER":
            require(ref_id, "verification_ref_id")
            status, detail = _verify_with_digilocker(fid, guardian, str(ref_id))
        row = db.insert_returning(
            f"""
            INSERT INTO parental_verification_logs
                (id, child_principal_id_enc, child_principal_id_hmac,
                 guardian_principal_id_enc, guardian_principal_id_hmac, verification_mechanism,
                 provider_name, verification_ref_id_enc, proof_metadata_enc, fiduciary_id, verification_status)
            VALUES (uuid_generate_v4(), {pii.ENC_SQL}, {pii.HMAC_SQL}, {pii.ENC_SQL}, {pii.HMAC_SQL},
                    %s, %s, {db.enc_expr()}, {db.enc_expr()}, %s, %s)
            RETURNING id
            """,
            (
                *pii.enc_params(child),
                *pii.hmac_params(child),
                *pii.enc_params(guardian),
                *pii.hmac_params(guardian),
                mechanism,
                payload.get("provider_name") or ("DigiLocker" if mechanism == "DIGILOCKER" else None),
                # Guardian evidence is stored encrypted (db/35); the proof as its JSON text.
                *db.bind_encrypt(None if ref_id is None else str(ref_id)),
                *db.bind_encrypt(
                    json.dumps({**(payload.get("proof_metadata") or {}), "verification_detail": detail}, default=str)
                ),
                fid,
                status,
            ),
        )
        log_event(
            guardian,
            fid,
            "APP",
            None,
            "GUARDIAN_VERIFICATION_RECORDED",
            {"child_principal_id": child, "mechanism": mechanism, "status": status},
            initiator="PRINCIPAL" if ctx.auth_via_principal_jwt else "INTEGRATOR",
            source_ip=ctx.source_ip,
        )
        return {
            "success": True,
            "verification_log_id": str(row["id"]),
            "verification_status": status,
            "detail": detail,
        }

    def get_parental_verification(self, ctx: RequestContext) -> dict:
        """The guardian verification a minor's consent record rests on, masked.

        Ported from Consent-Manager. guardian_id and verification_ref_id are
        masked; the proof itself never leaves (only whether there is one). The
        values in the clear are reveal_user_id's, under audit."""
        _require_console_operator(ctx)
        record = _console_record(ctx, "verification_log_id, fiduciary_id")
        if not record.get("verification_log_id"):
            raise ApiError(404, "Not Found", "This consent record is not a minor's: it has no guardian verification.")
        row = db.one(
            f"""
            SELECT id, verification_mechanism, provider_name, verification_status, verified_at,
                   {pii.dec_sql("guardian_principal_id_enc")} AS guardian_id,
                   {pii.dec_sql("verification_ref_id_enc")} AS verification_ref_id,
                   {pii.dec_sql("proof_metadata_enc")} AS proof_metadata
            FROM parental_verification_logs WHERE id = %s AND fiduciary_id = %s
            """,
            (*db.bind_key(), *db.bind_key(), *db.bind_key(), record["verification_log_id"], record["fiduciary_id"]),
        )
        if not row:
            raise ApiError(404, "Not Found", "No guardian verification found for this consent record.")
        return {
            "verification_log_id": str(row["id"]),
            "verification_mechanism": row["verification_mechanism"],
            "provider_name": row["provider_name"],
            "verification_status": row["verification_status"],
            "verified_at": row["verified_at"].isoformat() if row.get("verified_at") else None,
            "guardian_id": pii.mask(row["guardian_id"]),
            "verification_ref_id": pii.mask(row["verification_ref_id"]),
            "has_proof_metadata": _has_proof_metadata(row["proof_metadata"]),
            "verification_detail": _verification_detail(row["proof_metadata"]),
        }
