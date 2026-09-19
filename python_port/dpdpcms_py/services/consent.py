from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from typing import Any

from .. import db
from ..audit import log_event
from ..context import RequestContext
from ..errors import ApiError
from ..security import principal_token
from .base import Service, page_limit, require
from .catalog import resolve_fiduciary


def _fid(ctx: RequestContext) -> str:
    return require(resolve_fiduciary(ctx), "fiduciary_id")


def _consent_row(row: dict | None) -> dict | None:
    return db.to_jsonable(row) if row else None


NOTIF_CONSENT_GIVEN = "CONSENT_GIVEN_NOTIFICATION"
NOTIF_WITHDRAWAL_ACK = "WITHDRAWAL_ACKNOWLEDGMENT"
NOTIF_ERASURE_REQUESTED = "ERASURE_REQUESTED_NOTIFICATION"

# Cessation-based retention window stamped on each purpose at withdrawal (Section
# 8(7)). Mirrors the Java build, which recorded a 1095-day expiry per purpose.
RETENTION_CESSATION_DAYS = 1095


def _point_granted(point: dict) -> bool:
    """Data points are stored as {data_point_id, consent_granted, consent_expiry}; an expired
    grant no longer counts. 'status' is accepted as an older alias for consent_granted."""
    granted = point.get("consent_granted")
    if granted is None:
        granted = str(point.get("status", "")).lower() in {"granted", "true", "consent_given"}
    if not granted:
        return False
    expiry = point.get("consent_expiry")
    if expiry:
        try:
            if datetime.fromisoformat(str(expiry).replace("Z", "+00:00")) <= datetime.now(UTC):
                return False
        except ValueError:
            pass
    return True


def _point_grants(point: dict, purpose_id: str) -> bool:
    """As above, for one specific purpose. 'id'/'purpose_id' are older aliases for data_point_id."""
    stored_id = point.get("data_point_id") or point.get("id") or point.get("purpose_id")
    if not stored_id or str(stored_id).lower() != purpose_id.lower():
        return False
    return _point_granted(point)


def _normalise_purpose_ids(payload: dict) -> list[str]:
    """Collect the purpose selection from 'purpose_ids' (array/string) and the legacy 'purpose_id' alias."""
    raw = payload.get("purpose_ids") or []
    if isinstance(raw, str):
        raw = [raw]
    ids = [str(item).strip() for item in raw if item is not None and str(item).strip()]
    single = payload.get("purpose_id")
    if single is not None and str(single).strip() and str(single).strip() not in ids:
        ids.append(str(single).strip())
    return ids


def _notify_principal(user_id: str, fiduciary_id: str, notification_type: str) -> None:
    db.execute(
        "INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type) VALUES ('PRINCIPAL', %s, %s, %s)",
        (user_id, fiduciary_id, notification_type),
    )


class ConsentService(Service):
    def record_consent(self, ctx: RequestContext) -> dict:
        payload = ctx.payload
        fid = _fid(ctx)
        user_id = require(payload.get("user_id"), "user_id")
        policy_id = require(payload.get("policy_id"), "policy_id")
        data_consents = require(payload.get("data_point_consents"), "data_point_consents")
        requested_version = payload.get("version") or payload.get("policy_version") or ""
        if requested_version:
            policy = db.one(
                "SELECT version FROM consent_policies WHERE id = %s AND version = %s", (policy_id, requested_version)
            )
            if not policy:
                raise ApiError(
                    400, "Bad Request", f"Policy version mismatch: no version '{requested_version}' for {policy_id}."
                )
            version = requested_version
        else:
            # Notice versioning: when the client does not state which notice the
            # principal agreed to, stamp the current (preferring ACTIVE) version so
            # the consent record always identifies the notice it points at.
            policy = db.one(
                "SELECT version FROM consent_policies WHERE id = %s ORDER BY (status = 'ACTIVE') DESC, effective_date DESC LIMIT 1",
                (policy_id,),
            )
            if not policy:
                raise ApiError(400, "Bad Request", f"Policy not found: {policy_id}.")
            version = policy["version"]
        age_category = str(payload.get("age_category") or "ADULT").upper()
        guardian_id = payload.get("guardian_id")
        if age_category == "MINOR":
            if guardian_id:
                pass
            else:
                parent_log = db.one(
                    "SELECT id FROM parental_verification_logs WHERE child_principal_id = %s AND fiduciary_id = %s LIMIT 1",
                    (user_id, fid),
                )
                if not parent_log:
                    raise ApiError(403, "Forbidden", "Guardian consent is required to record consent for a minor.")
        with db.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE consent_records SET is_active_consent = FALSE, last_updated_at = NOW() WHERE user_id = %s AND fiduciary_id = %s AND is_active_consent IS TRUE",
                (user_id, fid),
            )
            cur.execute(
                """
                INSERT INTO consent_records
                    (id, user_id, fiduciary_id, policy_id, policy_version, timestamp,
                     jurisdiction, language_selected, consent_status_general, consent_mechanism,
                     ip_address, user_agent, data_point_consents, is_active_consent,
                     verification_log_id, created_at, last_updated_at)
                VALUES (uuid_generate_v4(), %s, %s, %s, %s, NOW(), %s, %s, %s, %s,
                        %s, %s, %s, TRUE, %s, NOW(), NOW())
                RETURNING id
                """,
                (
                    user_id,
                    fid,
                    policy_id,
                    version,
                    payload.get("jurisdiction", "IN"),
                    payload.get("language_selected", "en"),
                    payload.get("consent_status_general", "CONSENT_GIVEN"),
                    payload.get("consent_mechanism", "CONSENT_GIVEN"),
                    payload.get("ip_address", "0.0.0.0"),
                    payload.get("user_agent"),
                    db.as_jsonb(data_consents),
                    payload.get("verification_log_id"),
                ),
            )
            cid = str(cur.fetchone()["id"])
            cur.execute(
                """
                INSERT INTO data_principal (user_id, fiduciary_id, last_consent_mechanism, age_category, guardian_id, verification_status)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (user_id, fiduciary_id) DO UPDATE SET
                    last_consent_mechanism = EXCLUDED.last_consent_mechanism,
                    age_category = EXCLUDED.age_category,
                    guardian_id = EXCLUDED.guardian_id,
                    verification_status = EXCLUDED.verification_status
                """,
                (
                    user_id,
                    fid,
                    payload.get("consent_mechanism", "CONSENT_GIVEN"),
                    age_category,
                    guardian_id,
                    payload.get("verification_status", "NOT_VERIFIED"),
                ),
            )
        _notify_principal(user_id, fid, NOTIF_CONSENT_GIVEN)
        log_event(user_id, fid, "APP", None, "CONSENT_GIVEN", {"policy_id": policy_id, "record_id": cid})
        return {"success": True, "data": {"consent_record_id": cid, "message": "Consent recorded successfully."}}

    def record_parent_consent(self, ctx: RequestContext) -> dict:
        payload = ctx.payload
        row = db.insert_returning(
            """
            INSERT INTO parental_verification_logs
                (id, child_principal_id, guardian_principal_id, verification_mechanism,
                 provider_name, verification_ref_id, proof_metadata, fiduciary_id)
            VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                require(payload.get("child_principal_id"), "child_principal_id"),
                require(payload.get("guardian_principal_id"), "guardian_principal_id"),
                require(payload.get("verification_mechanism"), "verification_mechanism"),
                payload.get("provider_name"),
                payload.get("verification_ref_id"),
                db.as_jsonb(payload.get("proof_metadata") or {}),
                _fid(ctx),
            ),
        )
        return {"success": True, "verification_log_id": str(row["id"])}

    def get_active_consent(self, ctx: RequestContext) -> dict:
        where = ["user_id = %s", "fiduciary_id = %s", "is_active_consent IS TRUE"]
        params: list[Any] = [require(ctx.payload.get("user_id"), "user_id"), _fid(ctx)]
        if ctx.payload.get("policy_id"):
            where.append("policy_id = %s")
            params.append(ctx.payload["policy_id"])
        row = db.one(
            f"SELECT * FROM consent_records WHERE {' AND '.join(where)} ORDER BY timestamp DESC LIMIT 1", params
        )
        if not row:
            raise ApiError(404, "Not Found", "No active consent found.")
        return _consent_row(row)

    def get_consent_record_details(self, ctx: RequestContext) -> dict:
        where = ["id = %s"]
        params: list[Any] = [require(ctx.payload.get("record_id"), "record_id")]
        if ctx.fiduciary_id:
            where.append("fiduciary_id = %s")
            params.append(ctx.fiduciary_id)
        row = db.one(f"SELECT * FROM consent_records WHERE {' AND '.join(where)}", params)
        if not row:
            raise ApiError(404, "Not Found", "Consent record not found.")
        return _consent_row(row)

    def list_consent_history(self, ctx: RequestContext) -> list[dict]:
        page, limit = page_limit(ctx.payload)
        rows = db.all(
            "SELECT * FROM consent_records WHERE user_id = %s AND fiduciary_id = %s ORDER BY timestamp DESC LIMIT %s OFFSET %s",
            (require(ctx.payload.get("user_id"), "user_id"), _fid(ctx), limit, (page - 1) * limit),
        )
        out = db.to_jsonable(rows)
        for item in out:
            item["sync_token"] = principal_token(str(item["fiduciary_id"]), item["user_id"])
        return out

    def list_consents(self, ctx: RequestContext) -> dict:
        """Cross-principal consent listing for the DPO console. Always scoped to one fiduciary."""
        payload = ctx.payload
        page, limit = page_limit(payload, 25)
        where = ["fiduciary_id = %s"]
        params: list[Any] = [_fid(ctx)]
        if payload.get("user_id"):
            where.append("user_id ILIKE %s")
            params.append(f"%{payload['user_id']}%")
        if payload.get("policy_id"):
            where.append("policy_id = %s")
            params.append(payload["policy_id"])
        if payload.get("status"):
            where.append("consent_status_general = %s")
            params.append(payload["status"])
        if payload.get("active_only"):
            where.append("is_active_consent IS TRUE")
        if payload.get("start_date"):
            where.append("timestamp >= %s::timestamp")
            params.append(payload["start_date"])
        if payload.get("end_date"):
            where.append("timestamp <= %s::timestamp")
            params.append(payload["end_date"])
        clause = " AND ".join(where)
        total = db.one(f"SELECT COUNT(*) AS count FROM consent_records WHERE {clause}", params)
        rows = db.all(
            f"""
            SELECT id AS record_id, user_id, policy_id, policy_version, consent_status_general,
                   is_active_consent, timestamp, language_selected, consent_mechanism,
                   jurisdiction, data_point_consents
            FROM consent_records WHERE {clause}
            ORDER BY timestamp DESC LIMIT %s OFFSET %s
            """,
            [*params, limit, (page - 1) * limit],
        )
        out = []
        for row in db.to_jsonable(rows):
            points = row.pop("data_point_consents", None) or []
            points = [p for p in points if isinstance(p, dict)]
            row["purposes_total"] = len(points)
            row["purposes_granted"] = sum(1 for p in points if _point_granted(p))
            out.append(row)
        return {"success": True, "data": out, "page": page, "limit": limit, "total": total["count"] if total else 0}

    def list_principals(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(
            db.all(
                "SELECT * FROM data_principal WHERE fiduciary_id = %s ORDER BY created_at DESC LIMIT %s",
                (_fid(ctx), int(ctx.payload.get("limit") or 20)),
            )
        )

    def link_user(self, ctx: RequestContext) -> dict:
        anon = require(ctx.payload.get("anonymous_user_id"), "anonymous_user_id")
        auth = require(ctx.payload.get("authenticated_user_id"), "authenticated_user_id")
        fid = _fid(ctx)
        db.execute(
            "UPDATE consent_records SET user_id = %s, last_updated_at = NOW() WHERE user_id = %s AND fiduciary_id = %s",
            (auth, anon, fid),
        )
        db.execute(
            """
            INSERT INTO data_principal (user_id, fiduciary_id, age_category, guardian_id, verification_status)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (user_id, fiduciary_id) DO UPDATE SET
                age_category = EXCLUDED.age_category,
                guardian_id = EXCLUDED.guardian_id,
                verification_status = EXCLUDED.verification_status
            """,
            (
                auth,
                fid,
                ctx.payload.get("age_category", "ADULT"),
                ctx.payload.get("guardian_id"),
                ctx.payload.get("verification_status", "NOT_VERIFIED"),
            ),
        )
        return {"success": True, "message": "User consent records linked successfully."}

    def validate_consent(self, ctx: RequestContext) -> dict:
        user_id = require(ctx.payload.get("user_id"), "user_id")
        purpose = require(ctx.payload.get("required_purpose_id"), "required_purpose_id")
        row = db.one(
            "SELECT id, data_point_consents FROM consent_records WHERE user_id = %s AND fiduciary_id = %s AND is_active_consent IS TRUE ORDER BY timestamp DESC LIMIT 1",
            (user_id, _fid(ctx)),
        )
        valid = False
        if row:
            points = row.get("data_point_consents") or []
            valid = any(_point_grants(p, purpose) for p in points if isinstance(p, dict))
        db.execute(
            "INSERT INTO consent_validations (fiduciary_id, user_id, purpose_id, status) VALUES (%s, %s, %s, %s)",
            (_fid(ctx), user_id, purpose, "VALID" if valid else "INVALID"),
        )
        return {"valid": valid, "status": "VALID" if valid else "INVALID", "required_purpose_id": purpose}

    def withdraw_consent(self, ctx: RequestContext) -> dict:
        return self._withdraw(ctx, erasure=False)

    def erasure_request(self, ctx: RequestContext) -> dict:
        return self._withdraw(ctx, erasure=True)

    def _withdraw(self, ctx: RequestContext, erasure: bool) -> dict:
        fid = _fid(ctx)
        user_id = require(ctx.payload.get("user_id"), "user_id")
        purpose_ids = _normalise_purpose_ids(ctx.payload)
        status = "ERASURE_REQUESTED" if erasure else "WITHDRAWN"
        expiry = (datetime.now(UTC) + timedelta(days=RETENTION_CESSATION_DAYS)).isoformat()
        record_id = None
        with db.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, data_point_consents FROM consent_records WHERE user_id = %s AND fiduciary_id = %s AND is_active_consent IS TRUE ORDER BY timestamp DESC LIMIT 1",
                (user_id, fid),
            )
            row = cur.fetchone()
            if row:
                points = row["data_point_consents"] or []
                full_withdrawal = not purpose_ids
                updated: list[Any] = []
                for point in points:
                    if not isinstance(point, dict):
                        updated.append(point)
                        continue
                    stored_id = str(point.get("data_point_id") or point.get("id") or point.get("purpose_id") or "")
                    matches = full_withdrawal or any(stored_id.lower() == wanted.lower() for wanted in purpose_ids)
                    if matches:
                        point = dict(point)
                        point["consent_granted"] = False
                        point["consent_expiry"] = expiry
                        point["status"] = "withdrawn"
                    updated.append(point)
                remaining = [p for p in updated if isinstance(p, dict) and _point_granted(p)]
                is_active = bool(remaining)
                row_status = status if not remaining else "PARTIAL_WITHDRAWAL"
                cur.execute(
                    "UPDATE consent_records SET data_point_consents = %s, is_active_consent = %s, consent_status_general = %s, last_updated_at = NOW() WHERE id = %s",
                    (db.as_jsonb(updated), is_active, row_status, row["id"]),
                )
                record_id = str(row["id"])
            if erasure:
                targets = purpose_ids or ["ALL"]
                for target in targets:
                    cur.execute(
                        "INSERT INTO purge_requests (user_id, fiduciary_id, purpose_id, trigger_event, details) VALUES (%s, %s, %s, 'ErasureRequest', %s)",
                        (user_id, fid, target, ctx.payload.get("reason")),
                    )
        _notify_principal(user_id, fid, NOTIF_ERASURE_REQUESTED if erasure else NOTIF_WITHDRAWAL_ACK)
        log_event(
            user_id,
            fid,
            "APP",
            None,
            "ERASURE_REQUESTED" if erasure else "CONSENT_WITHDRAWN",
            {"reason": ctx.payload.get("reason"), "purpose_ids": purpose_ids, "record_id": record_id},
        )
        return {
            "success": True,
            "message": "Erasure request submitted." if erasure else "Consent withdrawn successfully.",
        }


class PrincipalService(Service):
    def list_active_fiduciaries(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(
            db.all(
                "SELECT id AS fiduciary_id, name, primary_domain FROM fiduciaries WHERE status = 'ACTIVE' ORDER BY name"
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
                 LATERAL jsonb_array_elements_text(e.data_subject_categories) AS cat
            WHERE e.fiduciary_id = %s
              AND e.status = 'active'
              AND trim(cat) <> ''
            ORDER BY label
            LIMIT 100
            """,
                (fid,),
            )
        )

    def request_principal_otp(self, ctx: RequestContext) -> dict:
        otp = f"{random.randint(100000, 999999)}"
        return {"success": True, "otp": otp, "message": "OTP generated."}

    def principal_login(self, ctx: RequestContext) -> dict:
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        user_id = require(ctx.payload.get("user_id"), "user_id")
        return {"success": True, "token": principal_token(fid, user_id), "user_id": user_id, "fiduciary_id": fid}


class WalletService(Service):
    def sync(self, ctx: RequestContext) -> dict:
        return {"success": True}

    def handle(self, ctx: RequestContext) -> Any:
        action = str(ctx.payload.get("action") or ctx.payload.get("_func") or "").upper()
        if action == "GET_CONSENT_DETAILS":
            return ConsentService().get_consent_record_details(ctx)
        if action in {"REVOKE_PURPOSE", "GLOBAL_ERASURE"}:
            return ConsentService().erasure_request(ctx)
        if action == "GRANT_CONSENT":
            return ConsentService().record_consent(ctx)
        if action == "GET_POLICY_PURPOSES":
            from .catalog import PolicyService

            return PolicyService().get_active_policy(ctx)
        return {"success": True}
