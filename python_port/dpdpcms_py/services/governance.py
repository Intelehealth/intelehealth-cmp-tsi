from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime

from .. import db
from ..audit import certificate_signature, get_log, list_logs, log_event, verify_chain
from ..config import settings
from ..context import RequestContext
from ..errors import ApiError
from ..netutil import validate_outbound_url
from ..security import hash_password, random_secret
from .base import Service, bind_principal_field, principal_list_filter, require, tenant_filter
from .catalog import resolve_fiduciary

API_KEY_COLUMNS = (
    "ak.id AS key_id, ak.fiduciary_id, ak.app_id, ap.name AS app_name, ak.description, "
    "ak.permissions, ak.status, ak.created_at, ak.expires_at, ak.last_used_at, ak.revoked_at"
)


def api_key_id(payload: dict) -> str:
    """The console and the validator schemas both use 'key_id'; older callers sent 'api_key'."""
    return require(payload.get("key_id") or payload.get("api_key"), "key_id")


class ApiKeyService(Service):
    def generate_api_key(self, ctx: RequestContext) -> dict:
        secret = random_secret()
        fiduciary_id = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        app_id = ctx.payload.get("app_id") or None
        permissions = ctx.payload.get("permissions") or ["READ"]
        row = db.insert_returning(
            """
            INSERT INTO api_keys
                (id, key_value, fiduciary_id, app_id, description, permissions, status, created_at, expires_at)
            VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, 'ACTIVE', NOW(), %s)
            RETURNING id
            """,
            (
                hash_password(secret),
                fiduciary_id,
                app_id,
                ctx.payload.get("description"),
                db.as_jsonb(permissions),
                ctx.payload.get("expires_at"),
            ),
        )
        key_id = str(row["id"])
        return {
            "success": True,
            "data": {
                "key_id": key_id,
                "raw_api_key": secret,
                "permissions": permissions,
                "fiduciary_id": fiduciary_id,
                "app_id": app_id,
            },
            # Flat aliases kept for non-console callers.
            "api_key": key_id,
            "api_secret": secret,
        }

    def list_api_keys(self, ctx: RequestContext) -> list[dict]:
        # An empty fiduciary_id/status/search means "no filter" — the console sends "" for all three.
        sql = f"SELECT {API_KEY_COLUMNS} FROM api_keys ak LEFT JOIN apps ap ON ak.app_id = ap.id WHERE 1 = 1"
        params: list[object] = []
        fiduciary_id = (ctx.payload.get("fiduciary_id") or "").strip()
        if fiduciary_id:
            sql += " AND ak.fiduciary_id = %s"
            params.append(fiduciary_id)
        status = (ctx.payload.get("status") or "").strip()
        if status:
            sql += " AND ak.status = %s"
            params.append(status.upper())
        search = (ctx.payload.get("search") or "").strip()
        if search:
            sql += " AND ak.description ILIKE %s"
            params.append(f"%{search}%")
        sql += " ORDER BY ak.created_at DESC"
        return db.to_jsonable(db.all(sql, tuple(params)))

    def revoke_api_key(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        updated = db.execute(
            f"UPDATE api_keys SET status = 'REVOKED', revoked_at = NOW() WHERE id = %s{scope}",
            (api_key_id(ctx.payload), *scope_params),
        )
        if updated == 0:
            raise ApiError(404, "Not Found", "API key not found.")
        return {"success": True, "message": "API Key revoked successfully."}

    def get_api_key_details(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx, "ak.fiduciary_id")
        row = db.one(
            f"SELECT {API_KEY_COLUMNS} FROM api_keys ak LEFT JOIN apps ap ON ak.app_id = ap.id WHERE ak.id = %s{scope}",
            (api_key_id(ctx.payload), *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "API key not found.")
        return db.to_jsonable(row)

    def update_api_key_status(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        updated = db.execute(
            f"UPDATE api_keys SET status = %s WHERE id = %s{scope}",
            (require(ctx.payload.get("status"), "status"), api_key_id(ctx.payload), *scope_params),
        )
        if updated == 0:
            raise ApiError(404, "Not Found", "API key not found.")
        return {"success": True}


# SA-07: audit actions that make up the access and role-modification report.
ACCESS_REPORT_ACTIONS = {
    "LOGIN_SUCCESS",
    "LOGIN_FAILURE",
    "USER_CREATED",
    "USER_UPDATED",
    "USER_DEACTIVATED",
    "ROLE_CREATED",
    "ROLE_PERMISSIONS_UPDATED",
    "ROLE_DELETED",
    "MFA_ENROLL_STARTED",
    "MFA_ENABLED",
    "MFA_VERIFY_FAILED",
}


class AuditService(Service):
    def list_audit_logs(self, ctx: RequestContext) -> list[dict]:
        from .roles import require_audit_access

        require_audit_access(ctx)
        return list_logs(ctx.payload)

    def verify_audit_chain(self, ctx: RequestContext) -> dict:
        """LG-04: recompute the hash-chained ledger and report any break.

        SEC-10: a tenant-scoped DPO or auditor may verify its own tenant's
        rows (fiduciary_id is passed as a scope), while a global operator keeps
        the platform-wide view. Neither learns other tenants' row ids. The walk
        is newest-first so recent tampering cannot hide outside the limit.
        """
        from .roles import require_audit_access

        require_audit_access(ctx)
        limit = min(max(int(ctx.payload.get("limit") or 100_000), 1), 1_000_000)
        return verify_chain(limit, fiduciary_id=ctx.fiduciary_id)

    def list_recent_audit_logs(self, ctx: RequestContext) -> list[dict]:
        from .roles import require_audit_access

        require_audit_access(ctx)
        return list_logs(ctx.payload)

    def list_access_logs(self, ctx: RequestContext) -> list[dict]:
        from .roles import require_audit_access

        require_audit_access(ctx)
        return list_logs(ctx.payload)

    def get_audit_log(self, ctx: RequestContext) -> dict:
        from .roles import require_audit_access

        require_audit_access(ctx)
        row = get_log(require(ctx.payload.get("id"), "id"))
        if not row or (ctx.fiduciary_id and str(row.get("fiduciary_id")) != ctx.fiduciary_id):
            raise ApiError(404, "Not Found", "Audit log not found.")
        return row

    def get_audit_log_entry(self, ctx: RequestContext) -> dict:
        return self.get_audit_log(ctx)

    def list_access_report(self, ctx: RequestContext) -> dict:
        """SA-07: who signed in (or failed to), and every change to accounts,
        roles and MFA, for a date range. Tenant-scoped like every audit read."""
        from .roles import require_audit_access

        require_audit_access(ctx)
        where = ["audit_action = ANY(%s)"]
        params: list = [sorted(ACCESS_REPORT_ACTIONS)]
        if ctx.fiduciary_id:
            where.append("fiduciary_id = %s")
            params.append(ctx.fiduciary_id)
        elif ctx.payload.get("fiduciary_id"):
            where.append("fiduciary_id = %s")
            params.append(ctx.payload["fiduciary_id"])
        if ctx.payload.get("start_date"):
            where.append("timestamp >= %s::timestamp")
            params.append(ctx.payload["start_date"])
        if ctx.payload.get("end_date"):
            where.append("timestamp <= %s::timestamp")
            params.append(ctx.payload["end_date"])
        params.append(min(int(ctx.payload.get("limit") or 500), 5000))
        rows = db.to_jsonable(
            db.all(
                f"""
                SELECT id, timestamp, fiduciary_id, user_id, service_type, service_id, audit_action,
                       context_details, source_ip
                FROM audit_logs WHERE {" AND ".join(where)}
                ORDER BY timestamp DESC LIMIT %s
                """,
                params,
            )
        )
        summary: dict[str, int] = {}
        for row in rows:
            summary[row["audit_action"]] = summary.get(row["audit_action"], 0) + 1
        return {"success": True, "summary": summary, "events": rows}

    def log_event(self, ctx: RequestContext) -> dict:
        log_event(
            ctx.payload.get("user_id"),
            ctx.payload.get("fiduciary_id"),
            ctx.payload.get("service_type", "SYSTEM"),
            ctx.payload.get("service_id"),
            require(ctx.payload.get("audit_action"), "audit_action"),
            ctx.payload.get("context_details"),
            purpose_id=ctx.payload.get("purpose_id"),
            consent_status=ctx.payload.get("consent_status"),
            initiator=ctx.payload.get("initiator"),
            source_ip=ctx.source_ip,
        )
        return {"success": True}


class NotificationService(Service):
    def list_notifications(self, ctx: RequestContext) -> list[dict]:
        bind_principal_field(ctx, "user_id")
        recipient = principal_list_filter(ctx, "recipient_id") or ctx.payload.get("user_id")
        where = ["fiduciary_id = %s"]
        params = [require(resolve_fiduciary(ctx), "fiduciary_id")]
        if ctx.auth_via_principal_jwt:
            where.append("recipient_type = %s")
            params.append("PRINCIPAL")
        if recipient:
            where.append("recipient_id = %s")
            params.append(recipient)
        params.append(int(ctx.payload.get("limit") or 50))
        return db.to_jsonable(
            db.all(f"SELECT * FROM notifications WHERE {' AND '.join(where)} ORDER BY created_at DESC LIMIT %s", params)
        )

    def mark_notification_read(self, ctx: RequestContext) -> dict:
        # NT-05: the schema and the documented sample name the field `id`; older
        # callers send `notification_id`. Accept either.
        nid = require(ctx.payload.get("notification_id") or ctx.payload.get("id"), "notification_id")
        where = ["id = %s"]
        params: list = [nid]
        if ctx.fiduciary_id:
            where.append("fiduciary_id = %s")
            params.append(ctx.fiduciary_id)
        if ctx.auth_via_principal_jwt:
            where.append("recipient_type = %s")
            params.append("PRINCIPAL")
            where.append("recipient_id = %s")
            params.append(require(ctx.principal_user_id, "principal"))
        read = db.execute(f"UPDATE notifications SET read_at = NOW() WHERE {' AND '.join(where)}", params)
        if read:
            row = db.one(
                "SELECT recipient_id, fiduciary_id FROM notifications WHERE id = %s",
                (nid,),
            )
            if row:
                log_event(
                    row.get("recipient_id") or ctx.actor_email or "PRINCIPAL",
                    row["fiduciary_id"],
                    "APP",
                    str(ctx.payload.get("notification_id")),
                    "NOTIFICATION_ACKNOWLEDGED",
                    {"notification_id": ctx.payload.get("notification_id")},
                    initiator="PRINCIPAL" if ctx.auth_via_principal_jwt else "INTEGRATOR",
                    source_ip=ctx.source_ip,
                )
        return {"success": True}

    def set_notification_message(self, ctx: RequestContext) -> dict:
        db.execute(
            """
            INSERT INTO notification_message_templates (fiduciary_id, notification_type, messages, last_updated_at)
            VALUES (%s, %s, %s, NOW())
            ON CONFLICT (fiduciary_id, notification_type) DO UPDATE SET
                messages = EXCLUDED.messages, last_updated_at = NOW()
            """,
            (
                require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),
                require(ctx.payload.get("notification_type"), "notification_type"),
                db.as_jsonb(require(ctx.payload.get("messages"), "messages")),
            ),
        )
        return {"success": True}

    def get_notification_messages(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(
            db.all(
                "SELECT notification_type, messages, last_updated_at FROM notification_message_templates WHERE fiduciary_id = %s ORDER BY notification_type",
                (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),),
            )
        )

    def set_webhook_config(self, ctx: RequestContext) -> dict:
        webhook_url = require(ctx.payload.get("webhook_url"), "webhook_url")
        # SSRF guard at save time: the URL must be http(s) and resolve to a
        # public address. It is re-validated at dispatch time before every POST.
        try:
            validate_outbound_url(webhook_url, "webhook_url")
        except ValueError as exc:
            raise ApiError(400, "Bad Request", str(exc)) from None
        db.execute(
            f"""
            INSERT INTO webhook_configs (fiduciary_id, category, webhook_url, secret_enc, enabled, last_updated_at)
            VALUES (%s, %s, %s, {db.enc_expr()}, %s, NOW())
            ON CONFLICT (fiduciary_id, category) DO UPDATE SET
                webhook_url = EXCLUDED.webhook_url, secret_enc = EXCLUDED.secret_enc,
                enabled = EXCLUDED.enabled, last_updated_at = NOW()
            """,
            (
                require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),
                require(ctx.payload.get("category"), "category"),
                webhook_url,
                *db.bind_encrypt(ctx.payload.get("secret", "")),
                bool(ctx.payload.get("enabled", True)),
            ),
        )
        return {"success": True}

    def list_webhook_configs(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(
            db.all(
                "SELECT fiduciary_id, category, webhook_url, enabled, last_updated_at FROM webhook_configs WHERE fiduciary_id = %s",
                (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),),
            )
        )

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

    def dispatch_notification(self, ctx: RequestContext) -> dict:
        row = db.insert_returning(
            "INSERT INTO notifications (id, recipient_type, recipient_id, fiduciary_id, notification_type, created_at) VALUES (uuid_generate_v4(), %s, %s, %s, %s, NOW()) RETURNING id",
            (
                require(ctx.payload.get("recipient_type"), "recipient_type"),
                require(ctx.payload.get("recipient_id"), "recipient_id"),
                require(resolve_fiduciary(ctx), "fiduciary_id"),
                require(ctx.payload.get("notification_type"), "notification_type"),
            ),
        )
        return {"success": True, "notification_id": str(row["id"])}


class JobService(Service):
    def create_job(self, ctx: RequestContext) -> dict:
        row = db.insert_returning(
            """
            INSERT INTO jobs (id, fiduciary_id, job_type, subtype, status, start_date, end_date, input_payload, created_at)
            VALUES (uuid_generate_v4(), %s, %s, %s, 'PENDING', %s, %s, %s, NOW())
            RETURNING id
            """,
            (
                require(resolve_fiduciary(ctx), "fiduciary_id"),
                require(ctx.payload.get("job_type"), "job_type"),
                ctx.payload.get("subtype"),
                ctx.payload.get("start_date"),
                ctx.payload.get("end_date"),
                ctx.payload.get("input_payload"),
            ),
        )
        return {"success": True, "job_id": str(row["id"])}

    def list_jobs(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(
            db.all(
                "SELECT * FROM jobs WHERE fiduciary_id = %s ORDER BY created_at DESC LIMIT %s",
                (require(resolve_fiduciary(ctx), "fiduciary_id"), int(ctx.payload.get("limit") or 50)),
            )
        )

    def download_file(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        row = db.one(
            f"SELECT output_file_path FROM jobs WHERE id = %s{scope}",
            (require(ctx.payload.get("job_id"), "job_id"), *scope_params),
        )
        return db.to_jsonable(row or {})


class RopaService(Service):
    def create_entry(self, ctx: RequestContext) -> dict:
        row = db.insert_returning(
            """
            INSERT INTO ropa_entries
                (id, fiduciary_id, app_id, activity_name, purpose, legal_basis,
                 data_categories, data_subject_categories, retention_period_days,
                 retention_start_event, processors, cross_border_transfers,
                 security_measures, linked_policy_ids, dpo_id, status, version, created_at, updated_at)
            VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'draft', 1, NOW(), NOW())
            RETURNING id
            """,
            (
                require(resolve_fiduciary(ctx), "fiduciary_id"),
                ctx.payload.get("app_id"),
                require(ctx.payload.get("activity_name"), "activity_name"),
                require(ctx.payload.get("purpose"), "purpose"),
                require(ctx.payload.get("legal_basis"), "legal_basis"),
                db.as_jsonb(ctx.payload.get("data_categories") or []),
                db.as_jsonb(ctx.payload.get("data_subject_categories") or []),
                ctx.payload.get("retention_period_days"),
                ctx.payload.get("retention_start_event"),
                db.as_jsonb(ctx.payload.get("processors") or []),
                db.as_jsonb(ctx.payload.get("cross_border_transfers") or []),
                ctx.payload.get("security_measures"),
                db.as_jsonb(ctx.payload.get("linked_policy_ids") or []),
                ctx.payload.get("dpo_id"),
            ),
        )
        return {"success": True, "id": str(row["id"])}

    def update_entry(self, ctx: RequestContext) -> dict:
        rid = require(ctx.payload.get("id"), "id")
        fields = ["updated_at = NOW()", "version = version + 1"]
        params = []
        for key in [
            "activity_name",
            "purpose",
            "legal_basis",
            "retention_period_days",
            "retention_start_event",
            "security_measures",
            "status",
            "dpo_id",
        ]:
            if key in ctx.payload:
                fields.append(f"{key} = %s")
                params.append(ctx.payload[key])
        for key in [
            "data_categories",
            "data_subject_categories",
            "processors",
            "cross_border_transfers",
            "linked_policy_ids",
        ]:
            if key in ctx.payload:
                fields.append(f"{key} = %s")
                params.append(db.as_jsonb(ctx.payload[key]))
        scope, scope_params = tenant_filter(ctx)
        params.extend([rid, *scope_params])
        if db.execute(f"UPDATE ropa_entries SET {', '.join(fields)} WHERE id = %s{scope}", params) == 0:
            raise ApiError(404, "Not Found", "ROPA entry not found.")
        return {"success": True}

    def publish_entry(self, ctx: RequestContext) -> dict:
        entry_id = require(ctx.payload.get("id"), "id")
        scope, scope_params = tenant_filter(ctx)
        entry = db.one(
            f"SELECT fiduciary_id, linked_policy_ids FROM ropa_entries WHERE id = %s{scope}", (entry_id, *scope_params)
        )
        if not entry:
            raise ApiError(404, "Not Found", "ROPA entry not found.")
        db.execute("UPDATE ropa_entries SET status = 'active', updated_at = NOW() WHERE id = %s", (entry_id,))
        fiduciary_id = str(entry["fiduciary_id"])
        activated = [
            pid
            for pid in (entry.get("linked_policy_ids") or [])
            if self._activate_policy_if_complete(str(pid), fiduciary_id)
        ]
        log_event("DPO", fiduciary_id, "DPO_CONSOLE", fiduciary_id, "ROPA_ENTRY_PUBLISHED", f"id:{entry_id}")
        return {"success": True, "message": "ROPA entry published.", "activated_policies": activated}

    def _activate_policy_if_complete(self, policy_id: str, fiduciary_id: str) -> bool:
        """A policy goes live only once every ROPA entry that references it is active or retired."""
        pending = db.one(
            "SELECT COUNT(*) AS count FROM ropa_entries WHERE linked_policy_ids @> %s AND fiduciary_id = %s AND status NOT IN ('active', 'retired')",
            (db.as_jsonb([policy_id]), fiduciary_id),
        )
        if pending and pending["count"] > 0:
            return False
        updated = db.execute(
            "UPDATE consent_policies SET status = 'ACTIVE', last_updated_at = NOW() WHERE id = %s AND fiduciary_id = %s AND status = 'UNDER_REVIEW'",
            (policy_id, fiduciary_id),
        )
        if not updated:
            return False
        log_event("DPO", fiduciary_id, "DPO_CONSOLE", fiduciary_id, "POLICY_ACTIVATED_BY_DPO", f"policy:{policy_id}")
        return True

    def retire_entry(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        updated = db.execute(
            f"UPDATE ropa_entries SET status = 'retired', updated_at = NOW() WHERE id = %s{scope}",
            (require(ctx.payload.get("id"), "id"), *scope_params),
        )
        # SEC-12: a retire that did not happen is not reported as done.
        if updated == 0:
            raise ApiError(404, "Not Found", "ROPA entry not found.")
        return {"success": True}

    def list_entries(self, ctx: RequestContext) -> list[dict]:
        where = ["fiduciary_id = %s"]
        params = [require(resolve_fiduciary(ctx), "fiduciary_id")]
        if ctx.payload.get("status"):
            where.append("status = %s")
            params.append(ctx.payload["status"])
        if ctx.payload.get("legal_basis"):
            where.append("legal_basis = %s")
            params.append(ctx.payload["legal_basis"])
        params.append(int(ctx.payload.get("limit") or 50))
        return db.to_jsonable(
            db.all(f"SELECT * FROM ropa_entries WHERE {' AND '.join(where)} ORDER BY updated_at DESC LIMIT %s", params)
        )

    def get_entry(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        row = db.one(
            f"SELECT * FROM ropa_entries WHERE id = %s{scope}", (require(ctx.payload.get("id"), "id"), *scope_params)
        )
        if not row:
            raise ApiError(404, "Not Found", "ROPA entry not found.")
        return db.to_jsonable(row)

    def validate_completeness(self, ctx: RequestContext) -> dict:
        row = self.get_entry(ctx)
        required = [
            "activity_name",
            "purpose",
            "legal_basis",
            "data_categories",
            "data_subject_categories",
            "dpo_id",
        ]
        missing = [k for k in required if not row.get(k)]
        complete = not missing
        return {
            "is_complete": complete,
            "complete": complete,
            "missing": missing,
            "missing_fields": missing,
        }

    def export_ropa(self, ctx: RequestContext) -> str:
        rows = self.list_entries(ctx)
        output = io.StringIO()
        writer = csv.DictWriter(
            output, fieldnames=["id", "activity_name", "purpose", "legal_basis", "status", "version"]
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in writer.fieldnames})
        return output.getvalue()

    def derive_from_policy(self, ctx: RequestContext) -> dict:
        return {"success": True, "message": "ROPA derivation hook completed."}


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
        logs = list_logs({"fiduciary_id": fiduciary_id, "user_id": principal, "limit": 500})
        # SEC-10: never sign a ledger that does not verify. The chain check is
        # scoped to this fiduciary so a DPO needs no global access to issue.
        chain = verify_chain(limit=2_000_000, fiduciary_id=fiduciary_id)
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
            "principal_id": principal,
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
                "summary": {key: chain[key] for key in ("rows_checked", "legacy_rows_linkage_only", "truncated")},
            },
            "evidence_trail": evidence_trail,
            "signature_algorithm": "HMAC-SHA256",
        }
        # SEC-10: generation and verification share one canonicalisation rule.
        data["signature"] = certificate_signature(data)
        row = db.insert_returning(
            "INSERT INTO evidence_certificates (id, fiduciary_id, subject_principal_id, certifying_officer_id, case_ref_id, certificate_data, attestation_text) VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, %s) RETURNING id",
            (
                fiduciary_id,
                principal,
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
        return db.to_jsonable(
            db.all(
                "SELECT id, id AS certificate_id, fiduciary_id, subject_principal_id AS principal_id, generated_at AS timestamp, case_ref_id AS case_ref FROM evidence_certificates WHERE fiduciary_id = %s ORDER BY generated_at DESC",
                (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),),
            )
        )

    def get_certificate(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        row = db.one(
            f"SELECT * FROM evidence_certificates WHERE id = %s{scope}",
            (require(ctx.payload.get("id"), "id"), *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "Certificate not found.")
        out = db.to_jsonable(row)
        # The console views read certificate_id, data and attestation; keep the
        # raw row under `data` so the viewer renders the signed payload.
        try:
            data = row["certificate_data"]
            if isinstance(data, str):
                data = json.loads(data)
        except (ValueError, TypeError):
            data = {}
        out["data"] = data
        out["attestation"] = out.get("attestation_text")
        return out

    def verify_certificate(self, ctx: RequestContext) -> dict:
        """SEC-10: verify an evidence certificate's HMAC signature.

        Not a trust assertion about the ledger — that is verify_audit_chain's
        job — but the missing counterpart to generation: recompute the signature
        over the canonical JSON (the exact function generate_certificate used)
        and report whether the certificate is internally authentic and unchanged.
        """
        scope, scope_params = tenant_filter(ctx)
        row = db.one(
            f"SELECT certificate_data FROM evidence_certificates WHERE id = %s{scope}",
            (require(ctx.payload.get("id"), "id"), *scope_params),
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
        if expected != recomputed:
            return {"valid": False, "reason": "Signature mismatch — the certificate has been altered."}
        log_event(
            ctx.actor_email or "DPO",
            ctx.fiduciary_id,
            "DPO_CONSOLE",
            None,
            "EVIDENCE_CERTIFICATE_VERIFIED",
            {"certificate_id": str(require(ctx.payload.get("id"), "id"))},
            source_ip=ctx.source_ip,
        )
        return {"valid": True, "signature_algorithm": data.get("signature_algorithm"), "signature": expected}
