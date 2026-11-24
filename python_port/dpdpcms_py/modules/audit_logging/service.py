from __future__ import annotations

from dpdpcms_py.kernel import db
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    Service,
    require,
)
from dpdpcms_py.modules.administration.api import authenticated_user_id
from dpdpcms_py.modules.audit_logging.ledger import (
    SOURCE_IP_SQL,
    get_log,
    latest_chain_verification,
    ledger_source,
    list_logs,
    log_event,
    verify_chain,
)

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
    # R6-c: Data Principal sign-ins to the rights portal, and who read the
    # audit ledger itself.
    "PRINCIPAL_LOGIN_SUCCESS",
    "PRINCIPAL_LOGIN_FAILURE",
    "AUDIT_LOG_READ",
}


def _audited_read(ctx: RequestContext, rows: list[dict], what: str) -> list[dict]:
    """R6-c: reading the audit ledger is itself an audited event."""
    filters = {
        k: ctx.payload.get(k)
        for k in (
            "fiduciary_id",
            "user_id",
            "audit_action",
            "purpose_id",
            "start_date",
            "end_date",
            "limit",
            "id",
            "consent_record_id",
        )
        if ctx.payload.get(k) not in (None, "")
    }
    log_event(
        authenticated_user_id(ctx) or ctx.actor_email or "OPERATOR",
        ctx.fiduciary_id or ctx.payload.get("fiduciary_id"),
        "ADMIN_CONSOLE",
        None,
        "AUDIT_LOG_READ",
        {"read": what, "filters": filters, "rows_returned": len(rows)},
        source_ip=ctx.source_ip,
    )
    return rows


class AuditService(Service):
    def list_audit_logs(self, ctx: RequestContext) -> list[dict]:
        from dpdpcms_py.modules.administration.api import require_audit_access

        require_audit_access(ctx)
        return _audited_read(ctx, list_logs(ctx.payload), "list_audit_logs")

    def verify_audit_chain(self, ctx: RequestContext) -> dict:
        """LG-04: recompute the hash-chained ledger and report any break.

        SEC-10: a tenant-scoped DPO or auditor may verify its own tenant's
        rows (fiduciary_id is passed as a scope), while a global operator keeps
        the platform-wide view. Neither learns other tenants' row ids. The walk
        is newest-first so recent tampering cannot hide outside the limit.
        """
        from dpdpcms_py.modules.administration.api import require_audit_access

        require_audit_access(ctx)
        limit = min(max(int(ctx.payload.get("limit") or 100_000), 1), 1_000_000)
        result = verify_chain(limit, fiduciary_id=ctx.fiduciary_id)
        # P6-12: the full-ledger walk runs in the worker; report its latest
        # verdict alongside this bounded on-demand window.
        result["last_full_verification"] = latest_chain_verification()
        if not ctx.fiduciary_id:
            # P16-02: the platform-wide view also reports the sealed pre-db/32 ledger.
            from dpdpcms_py.modules.audit_logging.ledger import latest_legacy_verification

            result["legacy_ledger_verification"] = latest_legacy_verification()
        return result

    def list_recent_audit_logs(self, ctx: RequestContext) -> list[dict]:
        from dpdpcms_py.modules.administration.api import require_audit_access

        require_audit_access(ctx)
        return _audited_read(ctx, list_logs(ctx.payload), "list_recent_audit_logs")

    def list_access_logs(self, ctx: RequestContext) -> list[dict]:
        from dpdpcms_py.modules.administration.api import require_audit_access

        require_audit_access(ctx)
        return _audited_read(ctx, list_logs(ctx.payload), "list_access_logs")

    def get_audit_log(self, ctx: RequestContext) -> dict:
        from dpdpcms_py.modules.administration.api import require_audit_access

        require_audit_access(ctx)
        row = get_log(require(ctx.payload.get("id"), "id"))
        if not row or (ctx.fiduciary_id and str(row.get("fiduciary_id")) != ctx.fiduciary_id):
            raise ApiError(404, "Not Found", "Audit log not found.")
        _audited_read(ctx, [row], "get_audit_log")
        return row

    def get_audit_log_entry(self, ctx: RequestContext) -> dict:
        return self.get_audit_log(ctx)

    def list_access_report(self, ctx: RequestContext) -> dict:
        """SA-07: who signed in (or failed to), and every change to accounts,
        roles and MFA, for a date range. Tenant-scoped like every audit read."""
        from dpdpcms_py.modules.administration.api import require_audit_access

        require_audit_access(ctx)
        where = ["audit_action = ANY(%s)"]
        params: list = [*db.bind_key(), sorted(ACCESS_REPORT_ACTIONS)]
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
                       context_details, {SOURCE_IP_SQL} AS source_ip
                FROM {ledger_source()} WHERE {" AND ".join(where)}
                ORDER BY timestamp DESC LIMIT %s
                """,
                params,
            )
        )
        summary: dict[str, int] = {}
        for row in rows:
            summary[row["audit_action"]] = summary.get(row["audit_action"], 0) + 1
        _audited_read(ctx, rows, "list_access_report")
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
