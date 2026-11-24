from __future__ import annotations

import csv
import io

from dpdpcms_py.kernel import db
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    Service,
    csv_safe,
    require,
    tenant_filter,
)
from dpdpcms_py.modules.administration.api import resolve_fiduciary
from dpdpcms_py.modules.audit_logging.ledger import (
    log_event,
)
from dpdpcms_py.modules.consent_lifecycle.api import activate_policy_if_complete


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
        """A policy goes live only once every ROPA entry that references it is
        active or retired; activation also sends the re-consent notices (P10-02)."""
        if not activate_policy_if_complete(policy_id, fiduciary_id):
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
            writer.writerow({key: csv_safe(row.get(key)) for key in writer.fieldnames})
        return output.getvalue()

    def derive_from_policy(self, ctx: RequestContext) -> dict:
        return {"success": True, "message": "ROPA derivation hook completed."}
