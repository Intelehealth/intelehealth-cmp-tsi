from __future__ import annotations

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    bind_principal_field,
    require,
    tenant_filter,
)
from dpdpcms_py.modules.administration.api import resolve_fiduciary
from dpdpcms_py.modules.audit_logging.ledger import log_event
from dpdpcms_py.modules.grievance.common import (
    _notify_grievance_assignee,
    _notify_grievance_stage,
    officer_can_handle_grievances,
)

GRIEVANCE_STATUSES = {"NEW", "IN_PROGRESS", "ESCALATED", "RESOLVED", "CLOSED"}


class ResolutionHandlers:
    def update_grievance_status(self, ctx: RequestContext) -> dict:
        gid = require(ctx.payload.get("grievance_id") or ctx.payload.get("id"), "grievance_id")
        status = str(require(ctx.payload.get("status"), "status")).upper()
        if status not in GRIEVANCE_STATUSES:
            raise ApiError(400, "Bad Request", f"status must be one of {sorted(GRIEVANCE_STATUSES)}.")
        resolution = ctx.payload.get("resolution_details")
        # GR-11: a grievance is closed only with a resolution summary for the principal.
        if status in {"RESOLVED", "CLOSED"} and not str(resolution or "").strip():
            raise ApiError(400, "Bad Request", "resolution_details is required to resolve or close a grievance.")
        scope, scope_params = tenant_filter(ctx)
        entry = self._log_entry(ctx, "STATUS_CHANGE", resolution, status=status)
        row = db.one(
            f"""
            UPDATE grievances SET status = %s, resolution_details = COALESCE(%s, resolution_details),
                   resolution_timestamp = CASE WHEN %s IN ('RESOLVED','CLOSED') THEN NOW() ELSE resolution_timestamp END,
                   communication_log = COALESCE(communication_log, '[]'::jsonb) || %s::jsonb,
                   last_updated_at = NOW()
            WHERE id = %s{scope}
            RETURNING {pii.dec_sql("user_id_enc")} AS user_id, fiduciary_id, reference_number, resolution_details,
                      language
            """,
            (status, resolution, status, db.as_jsonb([entry]), gid, *scope_params, *db.bind_key()),
        )
        if not row:
            raise ApiError(404, "Not Found", "Grievance not found.")
        # GR-10: the principal hears about every significant stage. GR-11: a
        # resolution notice carries the summary itself, not just the fact.
        context = None
        if status in {"RESOLVED", "CLOSED"}:
            context = {
                "grievance_id": str(gid),
                "reference_number": row.get("reference_number") or str(gid),
                "status_word": status.lower(),
                "resolution_details": row.get("resolution_details") or "",
            }
        _notify_grievance_stage(str(row["user_id"]), str(row["fiduciary_id"]), status, context, row.get("language"))
        log_event(
            ctx.actor_email or "DPO",
            str(row["fiduciary_id"]),
            "DPO_CONSOLE",
            None,
            "GRIEVANCE_STATUS_UPDATED",
            {"grievance_id": gid, "status": status},
            source_ip=ctx.source_ip,
        )
        return {"success": True}

    def assign_grievance(self, ctx: RequestContext) -> dict:
        # The grievance and the assignee must both belong to the grievance's tenant.
        gid = require(ctx.payload.get("grievance_id"), "grievance_id")
        operator_id = require(ctx.payload.get("operator_id"), "operator_id")
        officer = db.one("SELECT role, fiduciary_id FROM operators WHERE id = %s AND status = 'ACTIVE'", (operator_id,))
        if officer and not officer_can_handle_grievances(
            officer["role"], str(officer.get("fiduciary_id") or ctx.fiduciary_id or "") or None
        ):
            raise ApiError(400, "Bad Request", "The officer's role cannot act on grievances (needs grievance:write).")
        entry = self._log_entry(ctx, "ASSIGNED", None, operator_id=str(operator_id))
        # P7-05: assignment leaves the status as it is — the same outcome as the
        # auto-route in submit_grievance — so both paths agree. Work starting is a
        # separate, explicit update_grievance_status to IN_PROGRESS.
        row = db.one(
            f"""
            UPDATE grievances g SET assigned_dpo_user_id = o.id, last_updated_at = NOW(),
                   communication_log = COALESCE(g.communication_log, '[]'::jsonb) || %s::jsonb
            FROM operators o
            WHERE g.id = %s AND o.id = %s AND o.status = 'ACTIVE'
              AND (o.fiduciary_id = g.fiduciary_id OR o.role = 'ADMIN')
              AND (%s::uuid IS NULL OR g.fiduciary_id = %s::uuid)
            RETURNING {pii.dec_sql("g.user_id_enc")} AS user_id, g.fiduciary_id, g.reference_number, g.type,
                      g.status, g.language, o.id AS operator_id
            """,
            (db.as_jsonb([entry]), gid, operator_id, ctx.fiduciary_id, ctx.fiduciary_id, *db.bind_key()),
        )
        if not row:
            raise ApiError(404, "Not Found", "Grievance or operator not found.")
        fid = str(row["fiduciary_id"])
        _notify_grievance_stage(str(row["user_id"]), fid, "ASSIGNED", language=row.get("language"))
        # P7-05: the assignee hears about it too, with the grievance reference.
        _notify_grievance_assignee(str(row["operator_id"]), fid, str(gid), row.get("reference_number"), row.get("type"))
        log_event(
            ctx.actor_email or "DPO",
            fid,
            "DPO_CONSOLE",
            None,
            "GRIEVANCE_ASSIGNED",
            {"grievance_id": str(gid), "operator_id": str(row["operator_id"])},
            source_ip=ctx.source_ip,
        )
        return {"success": True, "status": row["status"]}

    def add_grievance_communication(self, ctx: RequestContext) -> dict:
        """GR-13: append a threaded entry (a message, a note, an action taken) to the
        grievance's action log without changing its status. A principal may add to
        their own grievance; the console and integrators to any in their tenant."""
        gid = require(ctx.payload.get("grievance_id") or ctx.payload.get("id"), "grievance_id")
        message = str(require(ctx.payload.get("message"), "message")).strip()
        if not message:
            raise ApiError(400, "Bad Request", "message must not be empty.")
        scope, scope_params = tenant_filter(ctx)
        if ctx.auth_via_principal_jwt:
            scope += f" AND {pii.match_sql('user_id')}"
            scope_params.extend(pii.hmac_params(ctx.principal_user_id))
        entry = self._log_entry(ctx, str(ctx.payload.get("kind") or "MESSAGE").upper(), message)
        row = db.one(
            f"""
            UPDATE grievances SET communication_log = COALESCE(communication_log, '[]'::jsonb) || %s::jsonb,
                   last_updated_at = NOW()
            WHERE id = %s{scope}
            RETURNING id
            """,
            (db.as_jsonb([entry]), gid, *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "Grievance not found.")
        return {"success": True, "entry": entry}

    def submit_grievance_feedback(self, ctx: RequestContext) -> dict:
        """GR-12: the principal rates how their resolved grievance was handled."""
        bind_principal_field(ctx, "user_id")
        user_id = require(ctx.payload.get("user_id"), "user_id")
        gid = require(ctx.payload.get("grievance_id"), "grievance_id")
        try:
            rating = int(require(ctx.payload.get("rating"), "rating"))
        except (TypeError, ValueError):
            raise ApiError(400, "Bad Request", "rating must be an integer from 1 to 5.") from None
        if not 1 <= rating <= 5:
            raise ApiError(400, "Bad Request", "rating must be an integer from 1 to 5.")
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        row = db.one(
            f"""
            UPDATE grievances SET feedback_rating = %s, feedback_comment = %s, feedback_at = NOW(), last_updated_at = NOW()
            WHERE id = %s AND fiduciary_id = %s AND {pii.match_sql("user_id")} AND status IN ('RESOLVED', 'CLOSED')
              AND feedback_at IS NULL
            RETURNING id
            """,
            (rating, ctx.payload.get("comment"), gid, fid, *pii.hmac_params(user_id)),
        )
        if not row:
            raise ApiError(
                409, "Conflict", "Feedback can be given once, by the complainant, after the grievance is resolved."
            )
        log_event(
            user_id,
            fid,
            "APP",
            None,
            "GRIEVANCE_FEEDBACK",
            {"grievance_id": gid, "rating": rating},
            initiator="PRINCIPAL" if ctx.auth_via_principal_jwt else "INTEGRATOR",
            source_ip=ctx.source_ip,
        )
        return {"success": True, "grievance_id": gid, "rating": rating}
