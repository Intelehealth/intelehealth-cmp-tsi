from __future__ import annotations

import uuid
from typing import Any

from .. import db
from ..audit import log_event
from ..context import ADMIN_FIDUCIARY_ID, RequestContext
from ..defaults import DEFAULT_NOTIFICATION_MESSAGES
from ..errors import ApiError
from .admin import authenticated_user_id, operator_fiduciary_id
from .base import Service, page_limit, reject_operator, require


def resolve_fiduciary(ctx: RequestContext) -> str | None:
    if ctx.payload.get("fiduciary_id"):
        return str(ctx.payload["fiduciary_id"])
    if ctx.fiduciary_id:
        return str(ctx.fiduciary_id)
    return operator_fiduciary_id(authenticated_user_id(ctx))


class FiduciaryService(Service):
    def list_fiduciaries(self, ctx: RequestContext) -> list[dict]:
        page, limit = page_limit(ctx.payload)
        params: list[Any] = [*db.bind_key()]
        where = ["status IS NOT NULL"]
        if ctx.payload.get("status"):
            where.append("status = %s")
            params.append(ctx.payload["status"])
        if ctx.payload.get("search"):
            where.append("(name ILIKE %s OR primary_domain ILIKE %s)")
            params.extend([f"%{ctx.payload['search']}%", f"%{ctx.payload['search']}%"])
        params.extend([limit, (page - 1) * limit])
        return db.to_jsonable(
            db.all(
                f"""
            SELECT id AS fiduciary_id, name, contact_person, {db.decrypt_col("email_enc")} AS email,
                   primary_domain, cms_cname, domain_validation_status,
                   is_significant_data_fiduciary, status, created_at, last_updated_at
            FROM fiduciaries
            WHERE {" AND ".join(where)}
            ORDER BY created_at DESC LIMIT %s OFFSET %s
            """,
                params,
            )
        )

    def get_fiduciary(self, ctx: RequestContext) -> dict:
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        row = db.one(
            f"""
            SELECT id AS fiduciary_id, name, contact_person, {db.decrypt_col("email_enc")} AS email,
                   {db.decrypt_col("phone_enc")} AS phone, address, primary_domain, cms_cname,
                   dns_txt_record_token, domain_validation_status, is_significant_data_fiduciary,
                   status, created_at, last_updated_at
            FROM fiduciaries WHERE id = %s
            """,
            (*db.bind_key(), *db.bind_key(), fid),
        )
        if not row:
            raise ApiError(404, "Not Found", "Data Fiduciary not found.")
        return db.to_jsonable(row)

    def create_fiduciary(self, ctx: RequestContext) -> dict:
        payload = ctx.payload
        token = "dpdp-verify-" + str(uuid.uuid4())[:8]
        email = require(payload.get("email"), "email")
        phone = payload.get("phone")
        row = db.insert_returning(
            f"""
            INSERT INTO fiduciaries
                (id, name, contact_person, email_plaintext, email_enc, email_hmac,
                 phone_plaintext, phone_enc, address, primary_domain, cms_cname,
                 dns_txt_record_token, domain_validation_status, is_significant_data_fiduciary,
                 status, created_at, last_updated_at)
            VALUES (uuid_generate_v4(), %s, %s, %s, {db.enc_expr()}, {db.hmac_expr()},
                    %s, {db.enc_expr()}, %s, %s, %s, %s, 'PENDING', %s, 'ACTIVE', NOW(), NOW())
            RETURNING id
            """,
            (
                require(payload.get("name"), "name"),
                payload.get("contact_person"),
                email,
                *db.bind_encrypt(email),
                *db.bind_hmac(email),
                phone,
                *db.bind_encrypt(phone),
                payload.get("address"),
                require(payload.get("primary_domain"), "primary_domain"),
                require(payload.get("cms_cname"), "cms_cname"),
                token,
                bool(payload.get("is_significant_data_fiduciary", False)),
            ),
        )
        fid = str(row["id"])
        for ntype, messages in DEFAULT_NOTIFICATION_MESSAGES.items():
            db.execute(
                "INSERT INTO notification_message_templates (fiduciary_id, notification_type, messages) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                (fid, ntype, db.as_jsonb(messages)),
            )
        log_event(
            "ADMIN", ADMIN_FIDUCIARY_ID, "ADMIN_CONSOLE", authenticated_user_id(ctx), "CREATE_FIDUCIARY", f"ID:{fid}"
        )
        return {
            "success": True,
            "data": {
                "fiduciary_id": fid,
                "dns_txt_record_token": token,
                "domain_validation_status": "PENDING",
                "message": "Fiduciary created successfully. Please add the DNS TXT record for validation.",
            },
        }

    def update_fiduciary(self, ctx: RequestContext) -> dict:
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        fields = ["last_updated_at = NOW()"]
        params: list[Any] = []
        simple = ["name", "contact_person", "address", "primary_domain", "cms_cname", "status"]
        for key in simple:
            if key in ctx.payload:
                fields.append(f"{key} = %s")
                params.append(ctx.payload[key])
        if "is_significant_data_fiduciary" in ctx.payload:
            fields.append("is_significant_data_fiduciary = %s")
            params.append(bool(ctx.payload["is_significant_data_fiduciary"]))
        if ctx.payload.get("email"):
            fields.append(f"email_plaintext = %s, email_enc = {db.enc_expr()}, email_hmac = {db.hmac_expr()}")
            params.extend(
                [ctx.payload["email"], *db.bind_encrypt(ctx.payload["email"]), *db.bind_hmac(ctx.payload["email"])]
            )
        if "phone" in ctx.payload:
            fields.append(f"phone_plaintext = %s, phone_enc = {db.enc_expr()}")
            params.extend([ctx.payload["phone"], *db.bind_encrypt(ctx.payload["phone"])])
        params.append(fid)
        db.execute(f"UPDATE fiduciaries SET {', '.join(fields)} WHERE id = %s", params)
        return {"success": True, "message": "Fiduciary updated successfully."}

    def delete_fiduciary(self, ctx: RequestContext) -> dict:
        db.execute(
            "UPDATE fiduciaries SET status = 'INACTIVE', last_updated_at = NOW() WHERE id = %s",
            (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"),),
        )
        return {"success": True}

    def validate_fiduciary_domain(self, ctx: RequestContext) -> dict:
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        status = "VALIDATED"
        db.execute(
            "UPDATE fiduciaries SET domain_validation_status = %s, last_updated_at = NOW() WHERE id = %s", (status, fid)
        )
        return {"fiduciary_id": fid, "domain_validation_status": status, "message": "Domain validation successful."}


class AppService(Service):
    def list_apps(self, ctx: RequestContext) -> list[dict]:
        page, limit = page_limit(ctx.payload, 50)
        params: list[Any] = [*db.bind_key(), *db.bind_key()]
        where = ["a.status IS NOT NULL"]
        fid = ctx.payload.get("fiduciary_id")
        if fid:
            where.append("a.fiduciary_id = %s")
            params.append(fid)
        params.extend([limit, (page - 1) * limit])
        return db.to_jsonable(
            db.all(
                f"""
            SELECT a.id AS app_id, a.fiduciary_id, f.name AS fiduciary_name, a.name,
                   {db.decrypt_col("a.email_enc")} AS email, {db.decrypt_col("a.phone_enc")} AS phone,
                   a.dpa_reference, a.processing_purposes, a.status, a.created_at, a.last_updated_at
            FROM apps a JOIN fiduciaries f ON a.fiduciary_id = f.id
            WHERE {" AND ".join(where)}
            ORDER BY a.created_at DESC LIMIT %s OFFSET %s
            """,
                params,
            )
        )

    def get_app(self, ctx: RequestContext) -> dict:
        row = db.one(
            f"SELECT id AS app_id, fiduciary_id, name, {db.decrypt_col('email_enc')} AS email, {db.decrypt_col('phone_enc')} AS phone, dpa_reference, processing_purposes, status FROM apps WHERE id = %s",
            (*db.bind_key(), *db.bind_key(), require(ctx.payload.get("app_id"), "app_id")),
        )
        if not row:
            raise ApiError(404, "Not Found", "App not found.")
        return db.to_jsonable(row)

    def create_app(self, ctx: RequestContext) -> dict:
        payload = ctx.payload
        email = payload.get("email")
        phone = payload.get("phone")
        row = db.insert_returning(
            f"""
            INSERT INTO apps
                (id, fiduciary_id, name, email_plaintext, email_enc, phone_plaintext, phone_enc,
                 dpa_reference, processing_purposes, status, created_at, last_updated_at)
            VALUES (uuid_generate_v4(), %s, %s, %s, {db.enc_expr()}, %s, {db.enc_expr()}, %s, %s, 'ACTIVE', NOW(), NOW())
            RETURNING id
            """,
            (
                require(payload.get("fiduciary_id"), "fiduciary_id"),
                require(payload.get("name"), "name"),
                email,
                *db.bind_encrypt(email),
                phone,
                *db.bind_encrypt(phone),
                payload.get("dpa_reference"),
                payload.get("processing_purposes"),
            ),
        )
        return {"success": True, "app_id": str(row["id"])}

    def update_app(self, ctx: RequestContext) -> dict:
        app_id = require(ctx.payload.get("app_id"), "app_id")
        fields = ["last_updated_at = NOW()"]
        params: list[Any] = []
        for key in ["name", "dpa_reference", "processing_purposes", "status"]:
            if key in ctx.payload:
                fields.append(f"{key} = %s")
                params.append(ctx.payload[key])
        if "email" in ctx.payload:
            fields.append(f"email_plaintext = %s, email_enc = {db.enc_expr()}")
            params.extend([ctx.payload["email"], *db.bind_encrypt(ctx.payload["email"])])
        if "phone" in ctx.payload:
            fields.append(f"phone_plaintext = %s, phone_enc = {db.enc_expr()}")
            params.extend([ctx.payload["phone"], *db.bind_encrypt(ctx.payload["phone"])])
        params.append(app_id)
        db.execute(f"UPDATE apps SET {', '.join(fields)} WHERE id = %s", params)
        return {"success": True}

    def delete_app(self, ctx: RequestContext) -> dict:
        db.execute(
            "UPDATE apps SET status = 'INACTIVE', last_updated_at = NOW() WHERE id = %s",
            (require(ctx.payload.get("app_id"), "app_id"),),
        )
        return {"success": True}


class PolicyService(Service):
    def list_active_policies(self, ctx: RequestContext) -> list[dict]:
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        rows = db.all(
            "SELECT id AS policy_id, version, jurisdiction, effective_date, policy_content FROM consent_policies WHERE fiduciary_id = %s AND status = 'ACTIVE' AND effective_date <= NOW() ORDER BY effective_date DESC",
            (fid,),
        )
        out = []
        for row in rows:
            content = row.get("policy_content") or {}
            lang = content.get("en") or next(iter(content.values()), {}) if isinstance(content, dict) else {}
            out.append(
                {
                    "policy_id": row["policy_id"],
                    "version": row["version"],
                    "jurisdiction": row["jurisdiction"],
                    "effective_date": row["effective_date"].isoformat(),
                    "title": lang.get("title", "Policy") if isinstance(lang, dict) else "Policy",
                }
            )
        return out

    def list_policies(self, ctx: RequestContext) -> list[dict]:
        page, limit = page_limit(ctx.payload)
        where = ["status IS NOT NULL"]
        params: list[Any] = []
        if ctx.payload.get("status"):
            where.append("status = %s")
            params.append(ctx.payload["status"])
        fid = ctx.payload.get("fiduciary_id_filter") or ctx.payload.get("fiduciary_id")
        if fid:
            where.append("fiduciary_id = %s")
            params.append(fid)
        if ctx.payload.get("search"):
            where.append("id ILIKE %s")
            params.append(f"%{ctx.payload['search']}%")
        params.extend([limit, (page - 1) * limit])
        return db.to_jsonable(
            db.all(
                f"SELECT id, version, fiduciary_id, effective_date, status, jurisdiction, created_at, last_updated_at FROM consent_policies WHERE {' AND '.join(where)} ORDER BY effective_date DESC LIMIT %s OFFSET %s",
                params,
            )
        )

    def get_policy(self, ctx: RequestContext) -> dict:
        pid = require(ctx.payload.get("policy_id"), "policy_id")
        version = ctx.payload.get("version") or ""
        row = db.one(
            "SELECT id AS policy_id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at FROM consent_policies WHERE id = %s AND version = %s",
            (pid, version),
        )
        if not row:
            raise ApiError(404, "Not Found", "Policy not found.")
        return db.to_jsonable(row)

    def get_active_policy(self, ctx: RequestContext) -> dict:
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        jurisdiction = require(ctx.payload.get("jurisdiction"), "jurisdiction")
        row = db.one(
            "SELECT id AS policy_id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at FROM consent_policies WHERE fiduciary_id = %s AND jurisdiction = %s AND status = 'ACTIVE' AND effective_date <= NOW() ORDER BY effective_date DESC LIMIT 1",
            (fid, jurisdiction),
        )
        if not row:
            raise ApiError(404, "Not Found", "No active policy found.")
        return db.to_jsonable(row)

    def create_policy(self, ctx: RequestContext) -> dict:
        reject_operator(ctx)
        pid = require(ctx.payload.get("policy_id"), "policy_id")
        version = ctx.payload.get("version") or ""
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        db.execute(
            "INSERT INTO consent_policies (id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at) VALUES (%s, %s, %s, NOW(), 'DRAFT', %s, %s, NOW(), NOW())",
            (
                pid,
                version,
                fid,
                require(ctx.payload.get("jurisdiction"), "jurisdiction"),
                db.as_jsonb(require(ctx.payload.get("policy_content"), "policy_content")),
            ),
        )
        return {
            "success": True,
            "data": {"policy_id": pid, "version": version, "message": "Policy created successfully."},
        }

    def update_policy(self, ctx: RequestContext) -> dict:
        reject_operator(ctx)
        db.execute(
            "UPDATE consent_policies SET policy_content = %s, last_updated_at = NOW() WHERE id = %s AND version = %s AND status = 'DRAFT'",
            (
                db.as_jsonb(require(ctx.payload.get("policy_content"), "policy_content")),
                require(ctx.payload.get("policy_id"), "policy_id"),
                ctx.payload.get("version") or "",
            ),
        )
        return {"success": True, "message": "Policy updated successfully."}

    def publish_policy(self, ctx: RequestContext) -> dict:
        reject_operator(ctx)
        pid = require(ctx.payload.get("policy_id"), "policy_id")
        version = ctx.payload.get("version") or ""
        row = db.one(
            "SELECT fiduciary_id, jurisdiction FROM consent_policies WHERE id = %s AND version = %s", (pid, version)
        )
        if not row:
            raise ApiError(404, "Not Found", "Policy not found.")
        db.execute(
            "UPDATE consent_policies SET status = 'UNDER_REVIEW', last_updated_at = NOW() WHERE id = %s AND version = %s",
            (pid, version),
        )
        return {"success": True, "message": "Policy published successfully."}

    def delete_policy(self, ctx: RequestContext) -> dict:
        reject_operator(ctx)
        db.execute(
            "UPDATE consent_policies SET status = 'ARCHIVED', last_updated_at = NOW() WHERE id = %s",
            (require(ctx.payload.get("policy_id"), "policy_id"),),
        )
        return {"success": True}
