from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import psycopg

from .. import db
from ..audit import log_event
from ..context import ADMIN_FIDUCIARY_ID, RequestContext
from ..defaults import DEFAULT_NOTIFICATION_MESSAGES
from ..errors import ApiError
from .admin import authenticated_user_id, operator_fiduciary_id
from .base import (
    Service,
    bind_principal_field,
    canonical_consent_points,
    canonical_purpose_id,
    page_limit,
    point_purpose_id,
    reject_operator,
    require,
    tenant_filter,
)
from .lifecycle import sync_purpose_lifecycle, validate_duration_flags


def resolve_fiduciary(ctx: RequestContext) -> str | None:
    # An authenticated client/principal is always scoped to its own fiduciary;
    # never let a body-supplied id override that. Admin (ctx.fiduciary_id unset)
    # still selects a fiduciary via the payload.
    if ctx.fiduciary_id:
        return str(ctx.fiduciary_id)
    if ctx.payload.get("fiduciary_id"):
        return str(ctx.payload["fiduciary_id"])
    return operator_fiduciary_id(authenticated_user_id(ctx))


def policy_fiduciary(ctx: RequestContext) -> str:
    """P13-01: the tenant a by-id policy operation acts on.

    consent_policies is keyed per tenant (P12-06), so a policy id alone can
    name rows in several tenants. A tenant-bound caller is pinned to its own
    tenant; a global ADMIN must name one in the payload, never "all of them".
    """
    return str(require(resolve_fiduciary(ctx), "fiduciary_id"))


def _policy_purposes(policy_content: Any) -> list[dict]:
    """Purpose objects of the first language block that declares any."""
    if not isinstance(policy_content, dict):
        return []
    for block in policy_content.values():
        if isinstance(block, dict):
            purposes = block.get("data_processing_purposes") or []
            if isinstance(purposes, list):
                return [p for p in purposes if isinstance(p, dict)]
    return []


def canonicalise_policy_purposes(policy_content: Any) -> Any:
    """P10-04: store every declared purpose id in its canonical spelling.

    Two purposes in one language block that differ only in case or spacing are
    one purpose to the consent gate, so declaring both is refused rather than
    silently merged.
    """
    if not isinstance(policy_content, dict):
        return policy_content
    out: dict[str, Any] = {}
    for lang, block in policy_content.items():
        if not isinstance(block, dict) or not isinstance(block.get("data_processing_purposes"), list):
            out[lang] = block
            continue
        seen: set[str] = set()
        purposes = []
        for purpose in block["data_processing_purposes"]:
            if isinstance(purpose, dict) and purpose.get("id") not in (None, ""):
                pid = canonical_purpose_id(purpose["id"])
                if pid in seen:
                    raise ApiError(
                        400,
                        "Bad Request",
                        f"Purpose id '{pid}' is declared more than once in '{lang}' (ids are case-insensitive).",
                    )
                seen.add(pid)
                purpose = {**purpose, "id": pid}
            purposes.append(purpose)
        out[lang] = {**block, "data_processing_purposes": purposes}
    return out


def _purpose_ids_by_language(policy_content: Any) -> dict[str, set[str]]:
    """Extract the set of declared purpose IDs per language block of a policy."""
    sets: dict[str, set[str]] = {}
    if not isinstance(policy_content, dict):
        return sets
    for lang, content in policy_content.items():
        if not isinstance(content, dict):
            continue
        purposes = content.get("data_processing_purposes") or []
        ids = {canonical_purpose_id(p.get("id")) for p in purposes if isinstance(p, dict) and p.get("id")}
        sets[str(lang)] = ids
    return sets


def check_language_parity(policy_content: Any) -> None:
    """Reject a multilingual policy whose languages declare different purpose IDs (Section 5(3))."""
    sets = _purpose_ids_by_language(policy_content)
    if len(sets) < 2:
        return
    base_lang, base_ids = next(iter(sets.items()))
    for lang, ids in sets.items():
        if ids != base_ids:
            raise ApiError(
                400, "Bad Request", f"Language Parity Failure: Purpose IDs in '{lang}' do not match '{base_lang}'."
            )


def derive_ropa_entries(fiduciary_id: str, policy_id: str, policy_content: Any) -> None:
    """Generate one draft ROPA entry per purpose declared in a policy, keyed on source_purpose_id."""
    if not isinstance(policy_content, dict):
        return
    lang_block = next(iter(policy_content.values()), {})
    if not isinstance(lang_block, dict):
        return
    purposes = lang_block.get("data_processing_purposes") or []
    for purpose in purposes:
        if not isinstance(purpose, dict):
            continue
        purpose_id = canonical_purpose_id(purpose.get("id"))
        if not purpose_id:
            continue
        existing = db.one(
            "SELECT id FROM ropa_entries WHERE fiduciary_id = %s AND lower(btrim(source_purpose_id)) = %s",
            (fiduciary_id, purpose_id),
        )
        if existing:
            continue
        db.execute(
            """
            INSERT INTO ropa_entries
                (id, fiduciary_id, activity_name, purpose, legal_basis, data_categories,
                 data_subject_categories, security_measures, linked_policy_ids, source_purpose_id,
                 status, version, created_at, updated_at)
            VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, %s, %s, %s, %s, 'draft', 1, NOW(), NOW())
            """,
            (
                fiduciary_id,
                purpose.get("name") or str(purpose_id),
                purpose.get("description") or purpose.get("name") or str(purpose_id),
                purpose.get("legal_basis") or "consent",
                db.as_jsonb(purpose.get("data_categories_involved") or []),
                db.as_jsonb(purpose.get("data_subject_categories") or []),
                purpose.get("security_measures"),
                db.as_jsonb([policy_id]),
                str(purpose_id),
            ),
        )


def queue_policy_change_notices(
    fiduciary_id: str, policy_id: str, new_version: str, reason: str | None = None
) -> dict[str, int]:
    """CU-02/CU-03: notify principals on a materially changed policy and require fresh consent.

    Finds every principal holding active consent on an earlier version of this
    policy, raises a PRINCIPAL notification and a PENDING re-consent request for
    each. Delivery is handled by the notification adapter worker; the principal
    responds through the /client request_reconsent endpoint.
    """
    fid = str(fiduciary_id)
    holders = db.all(
        """
        SELECT DISTINCT cr.user_id
        FROM consent_records cr
        WHERE cr.fiduciary_id = %s AND cr.policy_id = %s AND cr.policy_version <> %s
          AND cr.is_active_consent IS TRUE
        """,
        (fid, policy_id, new_version),
    )
    notified = 0
    for holder in holders:
        user_id = str(holder["user_id"])
        try:
            db.execute(
                """
                INSERT INTO reconsent_requests (fiduciary_id, policy_id, policy_version, user_id, reason)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (fiduciary_id, policy_id, policy_version, user_id) DO NOTHING
                """,
                (fid, policy_id, new_version, user_id, reason),
            )
            db.execute(
                """
                INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type)
                VALUES ('PRINCIPAL', %s, %s, 'POLICY_CHANGE_RECONSENT_REQUIRED')
                """,
                (user_id, fid),
            )
            notified += 1
        except Exception:
            continue
    return {"principals_affected": len(holders), "notified": notified}


def _requested_effective_date(value: Any) -> datetime | None:
    """P12-03: the effective_date a DPO asked for at create_policy, as an aware
    datetime (naive values read as UTC), or None when none was given."""
    if value in (None, ""):
        return None
    try:
        when = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApiError(400, "Bad Request", "effective_date must be an ISO 8601 date or timestamp.") from exc
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def served_policy_version(policy_id: str, fiduciary_id: str) -> str | None:
    """P11-03: the one version of a policy that is served - ACTIVE, in effect,
    and the newest such. get_active_policy and the consent gate both use it, so
    consent can only rest on the notice a principal is actually shown."""
    row = db.one(
        "SELECT version FROM consent_policies WHERE id = %s AND fiduciary_id = %s AND status = 'ACTIVE' AND effective_date <= NOW() ORDER BY effective_date DESC, last_updated_at DESC, created_at DESC LIMIT 1",
        (policy_id, str(fiduciary_id)),
    )
    return str(row["version"]) if row else None


def retire_superseded_versions(policy_id: str, fiduciary_id: str) -> list[str]:
    """P11-03: once a newer version is in force, the ones it supersedes are
    archived and their unanswered re-consent demands closed.

    Only versions already in effect are retired: a future-dated ACTIVE version
    leaves the current one served until its effective date. Consent records
    that rest on a retired version are untouched - they stay valid until the
    principal answers the re-consent request for the served version.
    """
    fid = str(fiduciary_id)
    served = served_policy_version(policy_id, fid)
    if served is None:
        return []
    retired = [
        str(r["version"])
        for r in db.all(
            "UPDATE consent_policies SET status = 'ARCHIVED', last_updated_at = NOW() WHERE id = %s AND fiduciary_id = %s AND status = 'ACTIVE' AND effective_date <= NOW() AND version <> %s RETURNING version",
            (policy_id, fid, served),
        )
    ]
    closed = db.execute(
        "UPDATE reconsent_requests SET status = 'CLOSED', responded_at = NOW() WHERE fiduciary_id = %s AND policy_id = %s AND policy_version <> %s AND status = 'PENDING'",
        (fid, policy_id, served),
    )
    if retired or closed:
        log_event(
            "SYSTEM",
            fid,
            "DPO_CONSOLE",
            None,
            "POLICY_VERSIONS_SUPERSEDED",
            {
                "policy_id": policy_id,
                "served_version": served,
                "archived_versions": retired,
                "reconsent_closed": closed,
            },
        )
    return retired


def retire_all_superseded_versions() -> dict[str, int]:
    """P11-03 (worker): a future-dated version supersedes the old one when its
    effective date arrives, which no API call marks - so the sweep does it."""
    archived = 0
    for row in db.all(
        "SELECT DISTINCT id, fiduciary_id FROM consent_policies p WHERE status = 'ACTIVE' AND effective_date <= NOW() AND EXISTS (SELECT 1 FROM consent_policies q WHERE q.id = p.id AND q.fiduciary_id = p.fiduciary_id AND q.status = 'ACTIVE' AND q.effective_date <= NOW() AND q.version <> p.version)"
    ):
        archived += len(retire_superseded_versions(str(row["id"]), str(row["fiduciary_id"])))
    return {"archived": archived}


def activate_policy_if_complete(policy_id: str, fiduciary_id: str) -> list[str]:
    """Activate the policy's UNDER_REVIEW version(s) once its ROPA is complete.

    A policy goes live only when every ROPA entry that references it is active
    or retired. P10-02: a version whose purpose set is unchanged (a wording-only
    notice change, the common case) derives no new draft entry, so it is
    complete the moment it is published - and it is the activation, not the
    publish, that sends the re-consent notices. Notifying while the version was
    still UNDER_REVIEW asked principals to consent to a notice the P9-02 guard
    then refused. Returns the versions activated.
    """
    fid = str(fiduciary_id)
    pending = db.one(
        "SELECT COUNT(*) AS count FROM ropa_entries WHERE linked_policy_ids @> %s AND fiduciary_id = %s AND status NOT IN ('active', 'retired')",
        (db.as_jsonb([policy_id]), fid),
    )
    if pending and pending["count"] > 0:
        return []
    rows = db.all(
        # P12-03: a version takes effect when it is activated, not when it was
        # drafted, so the version activated last is the one served. A future
        # effective_date the DPO asked for at create_policy is kept.
        # clock_timestamp: on an effective-date tie the version activated last is
        # the one served (P11-03), even inside the transaction that seeded both.
        "UPDATE consent_policies SET status = 'ACTIVE', effective_date = GREATEST(effective_date, NOW()), last_updated_at = clock_timestamp() WHERE id = %s AND fiduciary_id = %s AND status = 'UNDER_REVIEW' RETURNING version",
        (policy_id, fid),
    )
    versions = [str(r["version"]) for r in rows]
    # P11-03: the version just activated supersedes the one it replaces.
    if versions:
        retire_superseded_versions(policy_id, fid)
        # P12-03: only versions still ACTIVE after that are reported as activated.
        still_active = {
            str(r["version"])
            for r in db.all(
                "SELECT version FROM consent_policies WHERE id = %s AND fiduciary_id = %s AND status = 'ACTIVE'",
                (policy_id, fid),
            )
        }
        versions = [v for v in versions if v in still_active]
    # Notices go out only for a version already in force; a future-dated one is
    # announced with notify_policy_change once its effective date arrives.
    # P11-03: and only for the version now served - when two versions activate
    # together, the older one is superseded at once and is not announced.
    served = served_policy_version(policy_id, fid)
    in_force = {served} if served in versions else set()
    for version in [v for v in versions if v in in_force]:
        counts = queue_policy_change_notices(fid, policy_id, version)
        log_event(
            "SYSTEM",
            fid,
            "DPO_CONSOLE",
            None,
            "POLICY_CHANGE_NOTIFIED",
            {"policy_id": policy_id, "version": version, "on": "activation", **counts},
        )
    return versions


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
        fid = ctx.fiduciary_id or ctx.payload.get("fiduciary_id_filter") or ctx.payload.get("fiduciary_id")
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
        fid = policy_fiduciary(ctx)
        row = db.one(
            "SELECT id AS policy_id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at FROM consent_policies WHERE id = %s AND version = %s AND fiduciary_id = %s",
            (pid, version, fid),
        )
        if not row:
            raise ApiError(404, "Not Found", "Policy not found.")
        return db.to_jsonable(row)

    def get_active_policy(self, ctx: RequestContext) -> dict:
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        # P4-01: the wallet's GET_POLICY_PURPOSES sends policy_id, not
        # jurisdiction; prefer the named policy and fall back to the active
        # policy for the jurisdiction (defaulting to the system's IN default).
        policy_id = ctx.payload.get("policy_id")
        if policy_id:
            row = db.one(
                "SELECT id AS policy_id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at FROM consent_policies WHERE id = %s AND fiduciary_id = %s AND status = 'ACTIVE' AND effective_date <= NOW() ORDER BY effective_date DESC, last_updated_at DESC, created_at DESC LIMIT 1",
                (policy_id, fid),
            )
        else:
            jurisdiction = str(ctx.payload.get("jurisdiction") or "IN").upper()
            row = db.one(
                "SELECT id AS policy_id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at FROM consent_policies WHERE fiduciary_id = %s AND jurisdiction = %s AND status = 'ACTIVE' AND effective_date <= NOW() ORDER BY effective_date DESC LIMIT 1",
                (fid, jurisdiction),
            )
        if not row:
            raise ApiError(404, "Not Found", "No active policy found.")
        out = db.to_jsonable(row)
        # The wallet's GET_POLICY_PURPOSES consumes a purpose/persona view of
        # the policy; serve it from the same content the ROPA derivation used.
        content = row.get("policy_content") or {}
        out["purposes"] = [
            {
                "id": str(purpose.get("id")),
                "name": purpose.get("name"),
                "description": purpose.get("description"),
                "is_mandatory_for_service": bool(purpose.get("is_mandatory_for_service")),
            }
            for purpose in _policy_purposes(content)
            if purpose.get("id")
        ]
        lang_block = next(iter(content.values()), {})
        out["policy_title"] = (lang_block.get("title") if isinstance(lang_block, dict) else None) or out["policy_id"]
        out["personas"] = db.to_jsonable(
            db.all(
                """
                SELECT DISTINCT lower(replace(trim(cat), ' ', '_')) AS id, trim(cat) AS label
                FROM ropa_entries e,
                     LATERAL jsonb_array_elements_text(
                     CASE WHEN jsonb_typeof(e.data_subject_categories) = 'array'
                          THEN e.data_subject_categories ELSE '[]'::jsonb END) AS cat
                WHERE e.fiduciary_id = %s AND e.linked_policy_ids @> %s AND e.status = 'active'
                  AND trim(cat) <> ''
                ORDER BY label LIMIT 100
                """,
                (fid, db.as_jsonb([out["policy_id"]])),
            )
        )
        return out

    def create_policy(self, ctx: RequestContext) -> dict:
        reject_operator(ctx)
        pid = require(ctx.payload.get("policy_id"), "policy_id")
        version = ctx.payload.get("version") or ""
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        content = canonicalise_policy_purposes(require(ctx.payload.get("policy_content"), "policy_content"))
        check_language_parity(content)
        validate_duration_flags(content)  # PL-01: every purpose is open-ended or time-bound
        # P12-03: an effective_date the DPO supplies is honoured (a past one means
        # "on activation"); without one the version takes effect when activated.
        effective = _requested_effective_date(ctx.payload.get("effective_date"))
        try:
            db.execute(
                "INSERT INTO consent_policies (id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content, created_at, last_updated_at) VALUES (%s, %s, %s, COALESCE(%s, NOW()), 'DRAFT', %s, %s, NOW(), NOW())",
                (
                    pid,
                    version,
                    fid,
                    effective,
                    require(ctx.payload.get("jurisdiction"), "jurisdiction"),
                    db.as_jsonb(content),
                ),
            )
        except psycopg.errors.UniqueViolation as exc:
            # P12-06: a clash is the caller's own duplicate, never a 500.
            raise ApiError(409, "Conflict", f"Policy {pid} version {version} already exists.") from exc
        sync_purpose_lifecycle(fid, content)
        derive_ropa_entries(fid, pid, content)
        return {
            "success": True,
            "data": {"policy_id": pid, "version": version, "message": "Policy created successfully."},
        }

    def update_policy(self, ctx: RequestContext) -> dict:
        reject_operator(ctx)
        content = canonicalise_policy_purposes(require(ctx.payload.get("policy_content"), "policy_content"))
        check_language_parity(content)
        validate_duration_flags(content)  # PL-01: every purpose is open-ended or time-bound
        pid = require(ctx.payload.get("policy_id"), "policy_id")
        version = ctx.payload.get("version") or ""
        fid = policy_fiduciary(ctx)
        updated = db.execute(
            "UPDATE consent_policies SET policy_content = %s, last_updated_at = NOW() WHERE id = %s AND version = %s AND status = 'DRAFT' AND fiduciary_id = %s",
            (db.as_jsonb(content), pid, version, fid),
        )
        if updated == 0:
            raise ApiError(400, "Bad Request", "Policy not found or not in DRAFT status.")
        sync_purpose_lifecycle(fid, content)
        return {"success": True, "message": "Policy updated successfully."}

    def publish_policy(self, ctx: RequestContext) -> dict:
        reject_operator(ctx)
        pid = require(ctx.payload.get("policy_id"), "policy_id")
        version = ctx.payload.get("version") or ""
        fid = policy_fiduciary(ctx)
        row = db.one(
            "SELECT jurisdiction FROM consent_policies WHERE id = %s AND version = %s AND fiduciary_id = %s",
            (pid, version, fid),
        )
        if not row:
            raise ApiError(404, "Not Found", "Policy not found.")
        db.execute(
            "UPDATE consent_policies SET status = 'UNDER_REVIEW', last_updated_at = NOW() WHERE id = %s AND version = %s AND fiduciary_id = %s AND status = 'DRAFT'",
            (pid, version, fid),
        )
        # CU-02/CU-03: a materially changed policy must notify every principal
        # with active consent on an earlier version and request fresh consent.
        # P10-02: that happens when the version becomes ACTIVE - here, if its
        # ROPA is already complete, otherwise when the last ROPA entry is
        # published - so the principal is never asked to re-consent to a
        # notice record_consent would refuse.
        activated = activate_policy_if_complete(pid, fid)
        log_event(
            authenticated_user_id(ctx) or "DPO",
            fid,
            "DPO_CONSOLE",
            None,
            "POLICY_PUBLISHED",
            {"policy_id": pid, "version": version, "activated_versions": activated},
        )
        # P12-03: report what is stored, after any version this activation
        # superseded has been archived - never an optimistic ACTIVE.
        stored = db.one(
            "SELECT status FROM consent_policies WHERE id = %s AND version = %s AND fiduciary_id = %s",
            (pid, version, fid),
        )
        status = str(stored["status"]) if stored else "UNDER_REVIEW"
        return {
            "success": True,
            "message": {
                "ACTIVE": "Policy published successfully.",
                "ARCHIVED": "Policy published, but a newer active version supersedes it; it is archived and not served.",
            }.get(
                status,
                "Policy published; it activates, and re-consent notices go out, once its ROPA entries are published.",
            ),
            "data": {"status": status, "activated_versions": activated},
        }

    def notify_policy_change(self, ctx: RequestContext) -> dict:
        """CU-02: notify affected principals of a changed policy (idempotent replay)."""
        reject_operator(ctx)
        pid = require(ctx.payload.get("policy_id"), "policy_id")
        version = ctx.payload.get("version") or ""
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        # P10-02: never ask for re-consent to a version consent cannot rest on.
        # P11-03: and only to the version served now, retiring what it supersedes.
        if served_policy_version(pid, fid) != str(version):
            raise ApiError(
                409,
                "Conflict",
                f"Policy {pid} version {version} is not the active, in-effect notice; principals cannot re-consent to it yet.",
            )
        retire_superseded_versions(pid, fid)
        counts = queue_policy_change_notices(fid, pid, version, reason=ctx.payload.get("change_reason"))
        log_event(
            authenticated_user_id(ctx) or "DPO",
            fid,
            "DPO_CONSOLE",
            None,
            "POLICY_CHANGE_NOTIFIED",
            {"policy_id": pid, "version": version, **counts},
        )
        return {"success": True, "policy_id": pid, "version": version, **counts}

    def request_reconsent(self, ctx: RequestContext) -> dict:
        """CU-03: a principal confirms fresh affirmative consent on the new policy version."""
        payload = ctx.payload
        bind_principal_field(ctx, "user_id")
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        policy_id = require(payload.get("policy_id"), "policy_id")
        version = payload.get("version") or payload.get("policy_version") or ""
        user_id = require(payload.get("user_id"), "user_id")

        pending = db.one(
            "SELECT id FROM reconsent_requests WHERE fiduciary_id = %s AND policy_id = %s AND policy_version = %s AND user_id = %s AND status = 'PENDING'",
            (fid, policy_id, version, user_id),
        )
        if not pending:
            raise ApiError(
                400,
                "Bad Request",
                "No pending re-consent request exists for this principal, policy and version.",
            )

        consent = db.one(
            "SELECT policy_content FROM consent_policies WHERE id = %s AND version = %s AND fiduciary_id = %s",
            (policy_id, version, fid),
        )
        if not consent:
            raise ApiError(404, "Not Found", f"Policy {policy_id} version {version} not found.")
        declared = {canonical_purpose_id(p.get("id")) for p in _policy_purposes(consent.get("policy_content"))}

        data_consents = require(payload.get("data_point_consents"), "data_point_consents")
        if not isinstance(data_consents, list):
            raise ApiError(400, "Bad Request", "data_point_consents must be an array.")
        # P10-01: same alias rule as record_consent, applied before the check.
        data_consents = canonical_consent_points(data_consents)
        payload["data_point_consents"] = data_consents
        for point in data_consents:
            if not isinstance(point, dict):
                raise ApiError(400, "Bad Request", "data_point_consents entries must be objects.")
            purpose_id = point_purpose_id(point)
            if not purpose_id or purpose_id not in declared:
                raise ApiError(
                    400,
                    "Bad Request",
                    f"Purpose '{purpose_id}' is not declared in policy {policy_id} version {version} (CU-05).",
                )

        from .consent import ConsentService

        record = ConsentService().record_consent(ctx)
        record_id = record.get("data", {}).get("consent_record_id")
        db.execute(
            "UPDATE reconsent_requests SET status = 'GRANTED', responded_at = NOW(), consent_record_id = %s WHERE id = %s",
            (record_id, pending["id"]),
        )
        log_event(
            user_id,
            fid,
            "APP",
            None,
            "RECONSENT_GRANTED",
            {"policy_id": policy_id, "version": version, "reconsent_request_id": str(pending["id"])},
        )
        return {"success": True, "reconsent_request_id": str(pending["id"]), "status": "GRANTED"}

    def delete_policy(self, ctx: RequestContext) -> dict:
        reject_operator(ctx)
        pid = require(ctx.payload.get("policy_id"), "policy_id")
        updated = db.execute(
            "UPDATE consent_policies SET status = 'ARCHIVED', last_updated_at = NOW() WHERE id = %s AND fiduciary_id = %s",
            (pid, policy_fiduciary(ctx)),
        )
        # SEC-12: an archive that did not happen is not reported as done.
        if updated == 0:
            raise ApiError(404, "Not Found", "Policy not found.")
        return {"success": True}
