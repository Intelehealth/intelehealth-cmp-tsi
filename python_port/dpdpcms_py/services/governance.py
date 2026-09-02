from __future__ import annotations

import csv
import io
import uuid

from .. import db
from ..audit import get_log, list_logs, log_event
from ..context import RequestContext
from ..errors import ApiError
from ..security import hash_password, random_secret
from .base import Service, page_limit, require
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
            (hash_password(secret), fiduciary_id, app_id, ctx.payload.get("description"), db.as_jsonb(permissions), ctx.payload.get("expires_at")),
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
        db.execute("UPDATE api_keys SET status = 'REVOKED', revoked_at = NOW() WHERE id = %s", (api_key_id(ctx.payload),))
        return {"success": True, "message": "API Key revoked successfully."}

    def get_api_key_details(self, ctx: RequestContext) -> dict:
        row = db.one(f"SELECT {API_KEY_COLUMNS} FROM api_keys ak LEFT JOIN apps ap ON ak.app_id = ap.id WHERE ak.id = %s", (api_key_id(ctx.payload),))
        if not row:
            raise ApiError(404, "Not Found", "API key not found.")
        return db.to_jsonable(row)

    def update_api_key_status(self, ctx: RequestContext) -> dict:
        db.execute("UPDATE api_keys SET status = %s WHERE id = %s", (require(ctx.payload.get("status"), "status"), api_key_id(ctx.payload)))
        return {"success": True}


class AuditService(Service):
    def list_audit_logs(self, ctx: RequestContext) -> list[dict]:
        return list_logs(ctx.payload)

    def list_recent_audit_logs(self, ctx: RequestContext) -> list[dict]:
        return list_logs(ctx.payload)

    def list_access_logs(self, ctx: RequestContext) -> list[dict]:
        return list_logs(ctx.payload)

    def get_audit_log(self, ctx: RequestContext) -> dict:
        row = get_log(require(ctx.payload.get("id"), "id"))
        if not row:
            raise ApiError(404, "Not Found", "Audit log not found.")
        return row

    def get_audit_log_entry(self, ctx: RequestContext) -> dict:
        return self.get_audit_log(ctx)

    def log_event(self, ctx: RequestContext) -> dict:
        log_event(ctx.payload.get("user_id"), ctx.payload.get("fiduciary_id"), ctx.payload.get("service_type", "SYSTEM"), ctx.payload.get("service_id"), require(ctx.payload.get("audit_action"), "audit_action"), ctx.payload.get("context_details"))
        return {"success": True}


class NotificationService(Service):
    def list_notifications(self, ctx: RequestContext) -> list[dict]:
        recipient = ctx.payload.get("recipient_id") or ctx.payload.get("user_id")
        where = ["fiduciary_id = %s"]
        params = [require(resolve_fiduciary(ctx), "fiduciary_id")]
        if recipient:
            where.append("recipient_id = %s")
            params.append(recipient)
        params.append(int(ctx.payload.get("limit") or 50))
        return db.to_jsonable(db.all(f"SELECT * FROM notifications WHERE {' AND '.join(where)} ORDER BY created_at DESC LIMIT %s", params))

    def mark_notification_read(self, ctx: RequestContext) -> dict:
        db.execute("UPDATE notifications SET read_at = NOW() WHERE id = %s", (require(ctx.payload.get("notification_id"), "notification_id"),))
        return {"success": True}

    def set_notification_message(self, ctx: RequestContext) -> dict:
        db.execute(
            """
            INSERT INTO notification_message_templates (fiduciary_id, notification_type, messages, last_updated_at)
            VALUES (%s, %s, %s, NOW())
            ON CONFLICT (fiduciary_id, notification_type) DO UPDATE SET
                messages = EXCLUDED.messages, last_updated_at = NOW()
            """,
            (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"), require(ctx.payload.get("notification_type"), "notification_type"), db.as_jsonb(require(ctx.payload.get("messages"), "messages"))),
        )
        return {"success": True}

    def get_notification_messages(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(db.all("SELECT notification_type, messages, last_updated_at FROM notification_message_templates WHERE fiduciary_id = %s ORDER BY notification_type", (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),)))

    def set_webhook_config(self, ctx: RequestContext) -> dict:
        db.execute(
            f"""
            INSERT INTO webhook_configs (fiduciary_id, category, webhook_url, secret_enc, enabled, last_updated_at)
            VALUES (%s, %s, %s, {db.enc_expr()}, %s, NOW())
            ON CONFLICT (fiduciary_id, category) DO UPDATE SET
                webhook_url = EXCLUDED.webhook_url, secret_enc = EXCLUDED.secret_enc,
                enabled = EXCLUDED.enabled, last_updated_at = NOW()
            """,
            (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"), require(ctx.payload.get("category"), "category"), require(ctx.payload.get("webhook_url"), "webhook_url"), *db.bind_encrypt(ctx.payload.get("secret", "")), bool(ctx.payload.get("enabled", True))),
        )
        return {"success": True}

    def list_webhook_configs(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(db.all("SELECT fiduciary_id, category, webhook_url, enabled, last_updated_at FROM webhook_configs WHERE fiduciary_id = %s", (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),)))

    def set_rights_app_config(self, ctx: RequestContext) -> dict:
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
            (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"), require(ctx.payload.get("otp_mode"), "otp_mode"), ctx.payload.get("otp_message_template"), bool(ctx.payload.get("pca_qr_enabled", True))),
        )
        return {"success": True}

    def get_rights_app_config(self, ctx: RequestContext) -> dict:
        row = db.one("SELECT * FROM rights_app_config WHERE fiduciary_id = %s", (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),))
        return db.to_jsonable(row or {"fiduciary_id": ctx.payload.get("fiduciary_id"), "otp_mode": "DUMMY_OTP", "pca_qr_enabled": True})

    def dispatch_notification(self, ctx: RequestContext) -> dict:
        row = db.insert_returning(
            "INSERT INTO notifications (id, recipient_type, recipient_id, fiduciary_id, notification_type, created_at) VALUES (uuid_generate_v4(), %s, %s, %s, %s, NOW()) RETURNING id",
            (require(ctx.payload.get("recipient_type"), "recipient_type"), require(ctx.payload.get("recipient_id"), "recipient_id"), require(resolve_fiduciary(ctx), "fiduciary_id"), require(ctx.payload.get("notification_type"), "notification_type")),
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
            (require(resolve_fiduciary(ctx), "fiduciary_id"), require(ctx.payload.get("job_type"), "job_type"), ctx.payload.get("subtype"), ctx.payload.get("start_date"), ctx.payload.get("end_date"), ctx.payload.get("input_payload")),
        )
        return {"success": True, "job_id": str(row["id"])}

    def list_jobs(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(db.all("SELECT * FROM jobs WHERE fiduciary_id = %s ORDER BY created_at DESC LIMIT %s", (require(resolve_fiduciary(ctx), "fiduciary_id"), int(ctx.payload.get("limit") or 50))))

    def download_file(self, ctx: RequestContext) -> dict:
        row = db.one("SELECT output_file_path FROM jobs WHERE id = %s", (require(ctx.payload.get("job_id"), "job_id"),))
        return db.to_jsonable(row or {})


class RopaService(Service):
    def create_entry(self, ctx: RequestContext) -> dict:
        row = db.insert_returning(
            """
            INSERT INTO ropa_entries
                (id, fiduciary_id, app_id, activity_name, purpose, legal_basis,
                 data_categories, data_subject_categories, retention_period_days,
                 retention_start_event, processors, cross_border_transfers,
                 security_measures, linked_policy_ids, status, version, created_at, updated_at)
            VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'draft', 1, NOW(), NOW())
            RETURNING id
            """,
            (
                require(resolve_fiduciary(ctx), "fiduciary_id"), ctx.payload.get("app_id"),
                require(ctx.payload.get("activity_name"), "activity_name"), require(ctx.payload.get("purpose"), "purpose"),
                require(ctx.payload.get("legal_basis"), "legal_basis"), db.as_jsonb(ctx.payload.get("data_categories") or []),
                db.as_jsonb(ctx.payload.get("data_subject_categories") or []), ctx.payload.get("retention_period_days"),
                ctx.payload.get("retention_start_event"), db.as_jsonb(ctx.payload.get("processors") or []),
                db.as_jsonb(ctx.payload.get("cross_border_transfers") or []), ctx.payload.get("security_measures"),
                db.as_jsonb(ctx.payload.get("linked_policy_ids") or []),
            ),
        )
        return {"success": True, "id": str(row["id"])}

    def update_entry(self, ctx: RequestContext) -> dict:
        rid = require(ctx.payload.get("id"), "id")
        fields = ["updated_at = NOW()", "version = version + 1"]
        params = []
        for key in ["activity_name", "purpose", "legal_basis", "retention_period_days", "retention_start_event", "security_measures", "status"]:
            if key in ctx.payload:
                fields.append(f"{key} = %s")
                params.append(ctx.payload[key])
        for key in ["data_categories", "data_subject_categories", "processors", "cross_border_transfers", "linked_policy_ids"]:
            if key in ctx.payload:
                fields.append(f"{key} = %s")
                params.append(db.as_jsonb(ctx.payload[key]))
        params.append(rid)
        db.execute(f"UPDATE ropa_entries SET {', '.join(fields)} WHERE id = %s", params)
        return {"success": True}

    def publish_entry(self, ctx: RequestContext) -> dict:
        entry_id = require(ctx.payload.get("id"), "id")
        entry = db.one("SELECT fiduciary_id, linked_policy_ids FROM ropa_entries WHERE id = %s", (entry_id,))
        if not entry:
            raise ApiError(404, "Not Found", "ROPA entry not found.")
        db.execute("UPDATE ropa_entries SET status = 'active', updated_at = NOW() WHERE id = %s", (entry_id,))
        fiduciary_id = str(entry["fiduciary_id"])
        activated = [pid for pid in (entry.get("linked_policy_ids") or []) if self._activate_policy_if_complete(str(pid), fiduciary_id)]
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
        updated = db.execute("UPDATE consent_policies SET status = 'ACTIVE', last_updated_at = NOW() WHERE id = %s AND status = 'UNDER_REVIEW'", (policy_id,))
        if not updated:
            return False
        log_event("DPO", fiduciary_id, "DPO_CONSOLE", fiduciary_id, "POLICY_ACTIVATED_BY_DPO", f"policy:{policy_id}")
        return True

    def retire_entry(self, ctx: RequestContext) -> dict:
        db.execute("UPDATE ropa_entries SET status = 'retired', updated_at = NOW() WHERE id = %s", (require(ctx.payload.get("id"), "id"),))
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
        return db.to_jsonable(db.all(f"SELECT * FROM ropa_entries WHERE {' AND '.join(where)} ORDER BY updated_at DESC LIMIT %s", params))

    def get_entry(self, ctx: RequestContext) -> dict:
        row = db.one("SELECT * FROM ropa_entries WHERE id = %s", (require(ctx.payload.get("id"), "id"),))
        if not row:
            raise ApiError(404, "Not Found", "ROPA entry not found.")
        return db.to_jsonable(row)

    def validate_completeness(self, ctx: RequestContext) -> dict:
        row = self.get_entry(ctx)
        missing = [k for k in ["activity_name", "purpose", "legal_basis", "data_categories", "data_subject_categories"] if not row.get(k)]
        return {"is_complete": not missing, "missing": missing}

    def export_ropa(self, ctx: RequestContext) -> str:
        rows = self.list_entries(ctx)
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["id", "activity_name", "purpose", "legal_basis", "status", "version"])
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in writer.fieldnames})
        return output.getvalue()

    def derive_from_policy(self, ctx: RequestContext) -> dict:
        return {"success": True, "message": "ROPA derivation hook completed."}


class LegalService(Service):
    def generate_certificate(self, ctx: RequestContext) -> dict:
        logs = list_logs({"fiduciary_id": ctx.payload.get("fiduciary_id"), "user_id": ctx.payload.get("subject_principal_id"), "limit": 500})
        row = db.insert_returning(
            "INSERT INTO evidence_certificates (id, fiduciary_id, subject_principal_id, certifying_officer_id, case_ref_id, certificate_data, attestation_text) VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, %s) RETURNING id",
            (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"), require(ctx.payload.get("subject_principal_id"), "subject_principal_id"), ctx.payload.get("certifying_officer_id"), ctx.payload.get("case_ref_id"), db.as_jsonb({"logs": logs}), ctx.payload.get("attestation_text", "System-generated evidence certificate.")),
        )
        return {"success": True, "certificate_id": str(row["id"])}

    def list_certificates(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(db.all("SELECT id, fiduciary_id, subject_principal_id, generated_at, case_ref_id FROM evidence_certificates WHERE fiduciary_id = %s ORDER BY generated_at DESC", (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),)))

    def get_certificate(self, ctx: RequestContext) -> dict:
        row = db.one("SELECT * FROM evidence_certificates WHERE id = %s", (require(ctx.payload.get("id"), "id"),))
        if not row:
            raise ApiError(404, "Not Found", "Certificate not found.")
        return db.to_jsonable(row)
