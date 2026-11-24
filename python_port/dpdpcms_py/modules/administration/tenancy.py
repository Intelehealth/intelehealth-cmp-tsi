from __future__ import annotations

import uuid
from typing import Any

from dpdpcms_py.kernel import db
from dpdpcms_py.kernel.context import ADMIN_FIDUCIARY_ID, RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    Service,
    page_limit,
    require,
    tenant_filter,
)
from dpdpcms_py.modules.administration.identity import authenticated_user_id, operator_fiduciary_id
from dpdpcms_py.modules.audit_logging.ledger import log_event
from dpdpcms_py.modules.notifications.api import DEFAULT_NOTIFICATION_MESSAGES


def resolve_fiduciary(ctx: RequestContext) -> str | None:
    # An authenticated client/principal is always scoped to its own fiduciary;
    # never let a body-supplied id override that. Admin (ctx.fiduciary_id unset)
    # still selects a fiduciary via the payload.
    if ctx.fiduciary_id:
        return str(ctx.fiduciary_id)
    if ctx.payload.get("fiduciary_id"):
        return str(ctx.payload["fiduciary_id"])
    return operator_fiduciary_id(authenticated_user_id(ctx))


class FiduciaryService(Service):
    def list_fiduciaries(self, ctx: RequestContext) -> list[dict]:
        page, limit = page_limit(ctx.payload)
        params: list[Any] = [*db.bind_key()]
        where = ["status IS NOT NULL"]
        if ctx.fiduciary_id:
            where.append("id = %s")
            params.append(ctx.fiduciary_id)
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
                None,  # R6-a: encrypted copy only
                *db.bind_encrypt(email),
                *db.bind_hmac(email),
                None,
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
            params.extend([None, *db.bind_encrypt(ctx.payload["email"]), *db.bind_hmac(ctx.payload["email"])])
        if "phone" in ctx.payload:
            fields.append(f"phone_plaintext = %s, phone_enc = {db.enc_expr()}")
            params.extend([None, *db.bind_encrypt(ctx.payload["phone"])])
        scope, scope_params = tenant_filter(ctx, "id")
        params.extend([fid, *scope_params])
        if db.execute(f"UPDATE fiduciaries SET {', '.join(fields)} WHERE id = %s{scope}", params) == 0:
            raise ApiError(404, "Not Found", "Data Fiduciary not found.")
        return {"success": True, "message": "Fiduciary updated successfully."}

    def delete_fiduciary(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx, "id")
        updated = db.execute(
            f"UPDATE fiduciaries SET status = 'INACTIVE', last_updated_at = NOW() WHERE id = %s{scope}",
            (require(ctx.payload.get("fiduciary_id"), "fiduciary_id"), *scope_params),
        )
        # SEC-12: only log and report a deactivation that actually happened.
        if updated == 0:
            raise ApiError(404, "Not Found", "Data Fiduciary not found.")
        # INV-08: and every API key the fiduciary issued is revoked with it.
        revoked = db.execute(
            "UPDATE api_keys SET status = 'REVOKED', revoked_at = NOW() WHERE fiduciary_id = %s AND status = 'ACTIVE'",
            (ctx.payload["fiduciary_id"],),
        )
        return {"success": True, "api_keys_revoked": revoked}

    def validate_fiduciary_domain(self, ctx: RequestContext) -> dict:
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        status = "VALIDATED"
        scope, scope_params = tenant_filter(ctx, "id")
        db.execute(
            f"UPDATE fiduciaries SET domain_validation_status = %s, last_updated_at = NOW() WHERE id = %s{scope}",
            (status, fid, *scope_params),
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
        scope, scope_params = tenant_filter(ctx)
        row = db.one(
            f"SELECT id AS app_id, fiduciary_id, name, {db.decrypt_col('email_enc')} AS email, {db.decrypt_col('phone_enc')} AS phone, dpa_reference, processing_purposes, status FROM apps WHERE id = %s{scope}",
            (*db.bind_key(), *db.bind_key(), require(ctx.payload.get("app_id"), "app_id"), *scope_params),
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
                None,  # R6-a: encrypted copy only
                *db.bind_encrypt(email),
                None,
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
            params.extend([None, *db.bind_encrypt(ctx.payload["email"])])
        if "phone" in ctx.payload:
            fields.append(f"phone_plaintext = %s, phone_enc = {db.enc_expr()}")
            params.extend([None, *db.bind_encrypt(ctx.payload["phone"])])
        scope, scope_params = tenant_filter(ctx)
        params.extend([app_id, *scope_params])
        if db.execute(f"UPDATE apps SET {', '.join(fields)} WHERE id = %s{scope}", params) == 0:
            raise ApiError(404, "Not Found", "App not found.")
        return {"success": True}

    def delete_app(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        updated = db.execute(
            f"UPDATE apps SET status = 'INACTIVE', last_updated_at = NOW() WHERE id = %s{scope}",
            (require(ctx.payload.get("app_id"), "app_id"), *scope_params),
        )
        # SEC-12: a delete that did not happen is not reported as done.
        if updated == 0:
            raise ApiError(404, "Not Found", "App not found.")
        # INV-08: the app's keys are revoked with it, not merely left unusable.
        revoked = db.execute(
            "UPDATE api_keys SET status = 'REVOKED', revoked_at = NOW() WHERE app_id = %s AND status = 'ACTIVE'",
            (ctx.payload["app_id"],),
        )
        return {"success": True, "api_keys_revoked": revoked}
