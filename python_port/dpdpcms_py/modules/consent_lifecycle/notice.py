from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import psycopg
from dpdpcms_py.kernel import db
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    Service,
    canonical_purpose_id,
    page_limit,
    reject_operator,
    require,
)
from dpdpcms_py.modules.administration.api import authenticated_user_id, resolve_fiduciary
from dpdpcms_py.modules.audit_logging.ledger import log_event
from dpdpcms_py.modules.consent_lifecycle.policy_store import (
    _policy_purposes,
    queue_policy_change_notices,
    retire_superseded_versions,
    served_policy_version,
)
from dpdpcms_py.modules.consent_lifecycle.purpose_lifecycle import sync_purpose_lifecycle, validate_duration_flags
from dpdpcms_py.modules.consent_lifecycle.update import PolicyUpdateHandlers


def policy_fiduciary(ctx: RequestContext) -> str:
    """P13-01: the tenant a by-id policy operation acts on.

    consent_policies is keyed per tenant (P12-06), so a policy id alone can
    name rows in several tenants. A tenant-bound caller is pinned to its own
    tenant; a global ADMIN must name one in the payload, never "all of them".
    """
    return str(require(resolve_fiduciary(ctx), "fiduciary_id"))


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


class PolicyService(PolicyUpdateHandlers, Service):
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
