from __future__ import annotations

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.service import Service, require, tenant_filter
from dpdpcms_py.modules.administration.identity import authenticated_user_id, operator_fiduciary_id
from dpdpcms_py.modules.audit_logging.ledger import SOURCE_IP_SQL, ledger_source


def _count(sql: str, params: tuple = ()) -> int:
    row = db.one(sql, params)
    return int(row["count"]) if row else 0


class AdminDashService(Service):
    def get_admin_metrics(self, ctx: RequestContext) -> dict:
        # SEC-06: the console reads data.metrics.<name>; keep the envelope and
        # names identical to AdminDash.java. dashboard:read is held by DPO,
        # OPERATOR and AUDITOR, so the counts are scoped to the caller's tenant
        # exactly like get_dpo_metrics; only a global ADMIN sees platform-wide
        # totals. A tenant-scoped caller gets its own fiduciary counted once.
        def masked(sql: str, column: str, params: tuple = ()) -> int:
            if ctx.fiduciary_id:
                sql += f" AND {column} = %s"
                params = (*params, str(ctx.fiduciary_id))
            return _count(sql, params)

        return {
            "success": True,
            "metrics": {
                "active_fiduciaries": masked(
                    "SELECT COUNT(*) AS count FROM fiduciaries WHERE status IN ('ACTIVE', 'PENDING')",
                    "id",
                ),
                "active_processors": masked(
                    "SELECT COUNT(*) AS count FROM apps WHERE status = 'ACTIVE'",
                    "fiduciary_id",
                ),
                "failed_purges": masked(
                    "SELECT COUNT(*) AS count FROM purge_requests WHERE status = 'FAILED'",
                    "fiduciary_id",
                ),
            },
        }

    def get_dpo_metrics(self, ctx: RequestContext) -> dict:
        fid = ctx.payload.get("fiduciary_id") or ctx.fiduciary_id or operator_fiduciary_id(authenticated_user_id(ctx))
        start = ctx.payload.get("start_date") or "1970-01-01"
        end = ctx.payload.get("end_date") or "9999-12-31"
        window = (fid, start, end)
        return {
            "success": True,
            "metrics": {
                "active_policies": _count(
                    "SELECT COUNT(*) AS count FROM consent_policies WHERE fiduciary_id = %s AND status = 'ACTIVE' AND created_at BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "total_consents": _count(
                    "SELECT COUNT(*) AS count FROM consent_records WHERE fiduciary_id = %s AND timestamp BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "data_principals": _count(
                    "SELECT COUNT(*) AS count FROM data_principal WHERE fiduciary_id = %s AND created_at BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "purge_total": _count(
                    "SELECT COUNT(*) AS count FROM purge_requests WHERE fiduciary_id = %s AND initiated_at BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "purge_pending": _count(
                    "SELECT COUNT(*) AS count FROM purge_requests WHERE fiduciary_id = %s AND status NOT IN ('PURGE_COMPLETED','LEGAL_HOLD_APPLIED') AND initiated_at BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "grievances_total": _count(
                    "SELECT COUNT(*) AS count FROM grievances WHERE fiduciary_id = %s AND submission_timestamp BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "grievances_pending": _count(
                    "SELECT COUNT(*) AS count FROM grievances WHERE fiduciary_id = %s AND status NOT IN ('RESOLVED') AND submission_timestamp BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "ropa_active": _count(
                    "SELECT COUNT(*) AS count FROM ropa_entries WHERE fiduciary_id = %s AND status = 'active' AND created_at BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
                "ropa_draft": _count(
                    "SELECT COUNT(*) AS count FROM ropa_entries WHERE fiduciary_id = %s AND status = 'draft' AND created_at BETWEEN %s::timestamp AND %s::timestamp",
                    window,
                ),
            },
        }

    def list_pending_grievances(self, ctx: RequestContext) -> list[dict]:
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        rows = db.all(
            f"SELECT *, id AS grievance_id, {pii.dec_sql('user_id_enc')} AS user_id FROM grievances WHERE fiduciary_id = %s AND status IN ('NEW','IN_PROGRESS','ESCALATED') ORDER BY due_date ASC NULLS LAST LIMIT %s",
            (*db.bind_key(), fid, int(ctx.payload.get("limit") or 10)),
        )
        return [pii.principal_row(ctx, row, "user_id") for row in rows]

    def list_access_logs(self, ctx: RequestContext) -> list[dict]:
        from dpdpcms_py.modules.administration.roles import require_audit_access

        require_audit_access(ctx)
        limit = int(ctx.payload.get("limit") or 10)
        scope, scope_params = tenant_filter(ctx)
        # The whole ledger (archived years too), with the stored IP decrypted
        # as every other console audit read shows it.
        rows = db.all(
            f"SELECT *, {SOURCE_IP_SQL} AS source_ip_plain FROM {ledger_source()}"
            f" WHERE 1 = 1{scope} ORDER BY timestamp DESC LIMIT %s",
            (*db.bind_key(), *scope_params, limit),
        )
        for row in rows:
            row["source_ip"] = row.pop("source_ip_plain")
        return db.to_jsonable(rows)
