from __future__ import annotations

import hmac
import json
from datetime import UTC, datetime

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.config import settings
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    Service,
    require,
    tenant_filter,
)
from dpdpcms_py.modules.audit_logging.ledger import (
    certificate_signature,
    ledger_source,
    list_logs,
    log_event,
    principal_pseudonym,
    verify_chain,
)

# P6-12: certificate verification used to pull up to 2,000,000 unfiltered audit
# rows into the API process for every Verify Integrity press. The trail is now
# re-derived from the certificate's own hashes, and the global chain check is
# bounded to this window (the most recent rows, where tampering is attempted and
# noticed). Sized to be a cheap in-process scan, not a whole-ledger dump.
WINDOWED_CHAIN_CHECK_ROWS = 100_000


# P7-02: certificate paths anchor the walk on the certificate's own oldest trail
# entry and must examine every row from there to the head. This is the ceiling
# on that anchored walk; beyond it the certificate is refused as unverifiable
# (never certified on a partial window). The full ledger is walked off the
# request path by the worker (audit.record_chain_verification).
ANCHORED_CHAIN_CHECK_ROWS = 1_000_000


# The most events a certificate embeds; older ones are flagged as truncated.
CERTIFICATE_TRAIL_LIMIT = 500


# P16-04: the marker naming PII_LOOKUP_KEY as the key of a certificate's principal_id_hmac.
CERTIFICATE_SUBJECT_KEY = "PII_LOOKUP_KEY"


def _refuse_reason(chain: dict) -> str | None:
    """P7-02 / P8-04: why a chain result cannot back a certificate, if it cannot."""
    if chain.get("unexamined_tenant") or not chain.get("coverage_complete"):
        return (
            f"The audit chain walk examined {chain.get('rows_checked', 0)} of "
            f"{chain.get('rows_in_scope_total', 0)} rows in scope; a certificate cannot rest on an unexamined or partially examined chain."
        )
    return None


class LegalService(Service):
    def generate_certificate(self, ctx: RequestContext) -> dict:
        """LG-05/SA-14: crystallise a principal's hash-chained trail as evidence.

        The certificate embeds the verified chain segment (an evidence trail),
        environment metadata and an HMAC signature over that payload. The signing
        key is a deployment secret (`certificate_signing_key`), not a client
        secret the CMS serves; the algorithm and metadata are recorded so the
        certificate is verifiable rather than a bare log dump. SEC-10: the chain
        the certificate embeds is itself verified first — a certificate over a
        tampered ledger is refused rather than signed without complaint.
        """
        principal = require(ctx.payload.get("subject_principal_id"), "subject_principal_id")
        fiduciary_id = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        case_ref = ctx.payload.get("case_ref_id")
        logs = list_logs({"fiduciary_id": fiduciary_id, "user_id": principal, "limit": CERTIFICATE_TRAIL_LIMIT + 1})
        # The trail is the newest CERTIFICATE_TRAIL_LIMIT events; the signed
        # payload says so when older events exist, so the certificate never
        # silently presents a partial history as complete.
        trail_truncated = len(logs) > CERTIFICATE_TRAIL_LIMIT
        logs = logs[:CERTIFICATE_TRAIL_LIMIT]
        if not logs:
            raise ApiError(409, "Conflict", "No audit events exist for this principal; there is no trail to certify.")
        # SEC-10: never sign a ledger that does not verify. P7-02 / P8-04: the
        # walk is anchored on the oldest event the certificate embeds, so EVERY
        # row from there to the head (all tenants, for linkage) is examined; a
        # walk that could not reach the anchor is refused, not certified.
        chain = verify_chain(limit=ANCHORED_CHAIN_CHECK_ROWS, fiduciary_id=fiduciary_id, since=logs[-1]["timestamp"])
        refusal = _refuse_reason(chain)
        if refusal:
            raise ApiError(409, "Conflict", refusal)
        if not chain["intact"]:
            raise ApiError(
                409,
                "Conflict",
                "The audit chain for this fiduciary does not verify; a certificate cannot be issued over tampered evidence.",
            )
        fiduciary = db.one("SELECT name FROM fiduciaries WHERE id = %s", (fiduciary_id,))
        generated_at = datetime.now(UTC)
        evidence_trail = [
            {
                "ts": row["timestamp"].isoformat() if hasattr(row["timestamp"], "isoformat") else str(row["timestamp"]),
                "act": row["audit_action"],
                "hash": row.get("current_log_hash") or "",
            }
            for row in logs
        ]
        data = {
            # The signed payload binds the principal by HMAC, never in plaintext;
            # the readable id lives encrypted in subject_principal_id_enc.
            "principal_id_hmac": pii.hmac_hex(principal),
            # P16-04: which key made principal_id_hmac. Certificates without it
            # were made under DB_ENCRYPTION_KEY, before PII_LOOKUP_KEY existed.
            "principal_id_hmac_key": CERTIFICATE_SUBJECT_KEY,
            "case_ref_id": case_ref,
            "fiduciary_name": (fiduciary or {}).get("name") or "",
            "timestamp": generated_at.isoformat(),
            "environment": settings.environment,
            "brand": settings.brand_name,
            "system_metadata": {
                "environment": settings.environment,
                "generated_by": "TSI DPDP CMS",
                "node": "python_port",
                "chain_verified_at": generated_at.isoformat(),
                "summary": {
                    key: chain.get(key)
                    for key in ("rows_checked", "legacy_rows_linkage_only", "truncated", "anchored_since")
                },
            },
            "evidence_trail": evidence_trail,
            "trail_truncated": trail_truncated,
            "signature_algorithm": "HMAC-SHA256",
        }
        # SEC-10: generation and verification share one canonicalisation rule.
        data["signature"] = certificate_signature(data)
        row = db.insert_returning(
            "INSERT INTO evidence_certificates (id, fiduciary_id, subject_principal_id_enc, subject_principal_id_hmac,"
            " certifying_officer_id, case_ref_id, certificate_data, attestation_text)"
            f" VALUES (uuid_generate_v4(), %s, {pii.PID_VALUES}, %s, %s, %s, %s) RETURNING id",
            (
                fiduciary_id,
                *pii.pid_params(principal),
                ctx.operator_id or ctx.payload.get("certifying_officer_id"),
                case_ref,
                db.as_jsonb(data),
                ctx.payload.get("attestation_text", "System-generated evidence certificate."),
            ),
        )
        log_event(
            ctx.actor_email or principal,
            fiduciary_id,
            "DPO_CONSOLE",
            None,
            "EVIDENCE_CERTIFICATE_GENERATED",
            {"subject_principal_id": principal, "case_ref_id": case_ref},
            source_ip=ctx.source_ip,
        )
        return {"success": True, "certificate_id": str(row["id"])}

    def list_certificates(self, ctx: RequestContext) -> list[dict]:
        rows = db.all(
            f"SELECT id, id AS certificate_id, fiduciary_id, {pii.dec_sql('subject_principal_id_enc')} AS principal_id,"
            " generated_at AS timestamp, case_ref_id AS case_ref FROM evidence_certificates"
            " WHERE fiduciary_id = %s ORDER BY generated_at DESC",
            (*db.bind_key(), require(ctx.payload.get("fiduciary_id"), "fiduciary_id")),
        )
        return [pii.principal_row(ctx, row, "principal_id") for row in rows]

    def get_certificate(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        row = db.one(
            f"SELECT *, {pii.dec_sql('subject_principal_id_enc')} AS subject_principal_id"
            f" FROM evidence_certificates WHERE id = %s{scope}",
            (*db.bind_key(), require(ctx.payload.get("id"), "id"), *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "Certificate not found.")
        out = pii.principal_row(ctx, row, "subject_principal_id")
        # The console views read certificate_id, data and attestation; keep the
        # raw row under `data` so the viewer renders the signed payload.
        try:
            data = row["certificate_data"]
            if isinstance(data, str):
                data = json.loads(data)
        except (ValueError, TypeError):
            data = {}
        if isinstance(data, dict) and "principal_id" in data:
            # Certificates signed before principal_id_hmac name the principal in
            # plaintext; the stored copy stays intact, the console view is masked.
            data = {**data, "principal_id": pii.principal_view(ctx, data["principal_id"])}
        out["data"] = data
        out["attestation"] = out.get("attestation_text")
        return out

    def verify_certificate(self, ctx: RequestContext) -> dict:
        """SEC-10: verify an evidence certificate's HMAC signature.

        The signature is compared in constant time, and the certificate's
        embedded evidence trail is re-derived against `audit_logs` — so a
        certificate signed before the ledger was tampered with no longer returns
        "valid" on signature alone. A chain break, or any embedded trail hash
        that no longer exists in the ledger, is reported.
        """
        scope, scope_params = tenant_filter(ctx)
        row = db.one(
            f"SELECT certificate_data, fiduciary_id, {pii.dec_sql('subject_principal_id_enc')} AS subject"
            f" FROM evidence_certificates WHERE id = %s{scope}",
            (*db.bind_key(), require(ctx.payload.get("id"), "id"), *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "Certificate not found.")
        data = row.get("certificate_data")
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (ValueError, TypeError):
                data = {}
        if not isinstance(data, dict) or "signature" not in data:
            return {"valid": False, "reason": "Certificate carries no signature."}
        expected = data.get("signature")
        recomputed = certificate_signature(data)
        # SEC-10: constant-time comparison; a plain != let a timing side-channel
        # distinguish how much of the digest matched. compare_digest raises
        # TypeError on non-ASCII str, so coerce to bytes first — a tampered,
        # non-ASCII signature must read as INVALID, never 500.
        try:
            same = hmac.compare_digest(str(expected).encode("utf-8"), str(recomputed).encode("utf-8"))
        except (TypeError, ValueError):
            same = False
        if not same:
            return {"valid": False, "reason": "Signature mismatch — the certificate has been altered."}
        # The signed payload binds the principal by HMAC (legacy certificates
        # carry principal_id); the subject column must still be that principal.
        principal_id = data.get("principal_id")
        subject = row.get("subject")
        # Ruling O: an erased subject is not tampering. The binding (and the
        # per-principal completeness checks, which need the principal) are
        # skipped; the signature, trail hashes, order and chain still are not.
        subject_erased = str(subject or "").startswith("erased:")
        if not principal_id and data.get("principal_id_hmac") and not subject_erased:
            key = (
                settings.pii_lookup_key
                if data.get("principal_id_hmac_key") == CERTIFICATE_SUBJECT_KEY
                else settings.db_encryption_key
            )
            if not subject or pii.hmac_hex(str(subject), key) != data["principal_id_hmac"]:
                return {
                    "valid": False,
                    "reason": "The certificate's subject no longer matches its signed principal (erased or altered).",
                }
            principal_id = str(subject)

        # SEC-10: re-derive the embedded trail against the live ledger — ordering
        # AND completeness, not just "each hash exists". The certificate's trail
        # must be a prefix of the ledger's current trail for that principal
        # (newest-first), so an event that was omitted or reordered after signing
        # invalidates the certificate. Bounded (P6-12): we read only the rows the
        # certificate itself names, not the whole ledger.
        trail = data.get("evidence_trail") or []
        claimed = [
            str(entry.get("hash") or "").strip() for entry in trail if isinstance(entry, dict) and entry.get("hash")
        ]
        if claimed:
            # The trail may reach back into archived years (db/32, db/33).
            ledger = ledger_source()
            placeholders = ", ".join(["%s"] * len(claimed))
            rows = db.all(
                f"SELECT current_log_hash, timestamp FROM {ledger} "
                f"WHERE current_log_hash IN ({placeholders}) AND fiduciary_id = %s",
                (*claimed, str(row["fiduciary_id"])),
            )
            found = {str(r["current_log_hash"]): r for r in rows}
            missing = [h for h in claimed if h not in found]
            if missing:
                return {
                    "valid": False,
                    "reason": "Certificate embeds hashes no longer present in the audit ledger.",
                    "missing_hashes": missing[:10],
                }
            # Ordering: the certificate's newest-first trail must match the
            # ledger's timestamp order for those same rows.
            ledger_order = sorted(
                (str(r["current_log_hash"]) for r in found.values()),
                key=lambda h: found[h]["timestamp"] or "",
                reverse=True,
            )
            if ledger_order != claimed:
                return {
                    "valid": False,
                    "reason": "Certificate trail is not in the ledger's order — events were reordered after signing.",
                }
            # SEC-10 completeness: compare against the principal's ACTUAL trail
            # in the certificate's time range, not against the certificate's own
            # hashes. An event of this principal inside the signed range that is
            # missing from the trail means the trail is incomplete.
            if principal_id:
                ledger_trail = [
                    str(r["current_log_hash"])
                    for r in db.all(
                        f"SELECT current_log_hash FROM {ledger} WHERE fiduciary_id = %s AND user_id = %s"
                        " AND timestamp >= %s AND timestamp <= %s ORDER BY timestamp DESC, id DESC",
                        (
                            str(row["fiduciary_id"]),
                            principal_pseudonym(str(principal_id)),
                            found[claimed[-1]]["timestamp"],
                            found[claimed[0]]["timestamp"],
                        ),
                    )
                ]
                if ledger_trail != claimed:
                    return {
                        "valid": False,
                        "reason": "Certificate trail does not match the principal's ledger for the period it covers — events are missing or extra.",
                    }
                # Below the anchor: a trail that does not declare itself
                # truncated claims the principal's WHOLE history, so no earlier
                # event of theirs may exist.
                # Certificates issued before the marker existed carry no key and
                # may hold a capped trail, so the check applies only when the
                # signed payload explicitly says the trail is complete.
                if data.get("trail_truncated") is False and db.one(
                    f"SELECT 1 FROM {ledger} WHERE fiduciary_id = %s AND user_id = %s AND timestamp < %s LIMIT 1",
                    (str(row["fiduciary_id"]), principal_pseudonym(str(principal_id)), found[claimed[-1]]["timestamp"]),
                ):
                    return {
                        "valid": False,
                        "reason": "Certificate trail omits the principal's earlier events without declaring itself truncated.",
                    }
        # SEC-10: the chain these hashes anchor to must still verify. P6-12: the
        # walk is bounded (a window), not an unfiltered 2,000,000-row pull into
        # the API process. This certificate's OWN rows were just re-derived above;
        # the windowed global check still catches tampering in the recent ledger.
        # P7-02: a scoped report that examined ZERO of this tenant's rows (rows
        # pushed out of the window by other tenants) is not a clean bill of
        # health — the certificate is refused rather than verified on nothing.
        # P7-02 / P8-04: anchored on the certificate's oldest trail entry, so the
        # walk covers every row the certificate rests on; an incomplete walk is
        # "not verified", never "valid".
        if claimed:
            chain = verify_chain(
                limit=ANCHORED_CHAIN_CHECK_ROWS,
                fiduciary_id=str(row["fiduciary_id"]),
                since=found[claimed[-1]]["timestamp"],
            )
            refusal = _refuse_reason(chain)
        else:
            chain = verify_chain(limit=WINDOWED_CHAIN_CHECK_ROWS, fiduciary_id=str(row["fiduciary_id"]))
            refusal = (
                "The ledger window checked contained none of this fiduciary's rows; the certificate cannot be verified against an unexamined chain."
                if chain.get("unexamined_tenant")
                else None
            )
        if refusal:
            return {
                "valid": False,
                "verified": False,
                "reason": refusal,
                "chain_intact": None,
                "rows_checked": chain.get("rows_checked", 0),
                "rows_in_scope_total": chain.get("rows_in_scope_total", 0),
            }
        if not chain["intact"]:
            return {
                "valid": False,
                "reason": "The audit chain this certificate rests on no longer verifies; treat the certificate and its trail as compromised.",
                "chain_intact": False,
                "broken_count": chain.get("broken_count", 0),
                "foreign_broken_count": chain.get("foreign_broken_count", 0),
            }
        log_event(
            ctx.actor_email or "DPO",
            ctx.fiduciary_id,
            "DPO_CONSOLE",
            None,
            "EVIDENCE_CERTIFICATE_VERIFIED",
            {"certificate_id": str(require(ctx.payload.get("id"), "id"))},
            source_ip=ctx.source_ip,
        )
        return {
            "valid": True,
            "signature_algorithm": data.get("signature_algorithm"),
            "signature": expected,
            "trail_hashes_checked": len(claimed),
            "chain_intact": chain["intact"],
            **({"subject_erased": True} if subject_erased else {}),
        }
