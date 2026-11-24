from __future__ import annotations

from dpdpcms_py.kernel import db
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    require,
)
from dpdpcms_py.modules.administration.api import resolve_fiduciary
from dpdpcms_py.modules.audit_logging.ledger import log_event
from dpdpcms_py.modules.grievance.common import GRIEVANCE_TYPES, officer_can_handle_grievances


class RoutingHandlers:
    def set_grievance_routing(self, ctx: RequestContext) -> dict:
        """GR-07: route a complaint category to a department and its officer.

        `remove: true` deletes the rule, so the category falls back to the DPO.
        The officer must be ACTIVE and belong to the fiduciary.
        """
        fid = str(require(resolve_fiduciary(ctx), "fiduciary_id"))
        grievance_type = str(require(ctx.payload.get("grievance_type"), "grievance_type")).strip().upper()
        if grievance_type not in GRIEVANCE_TYPES:
            raise ApiError(400, "Bad Request", f"grievance_type must be one of {sorted(GRIEVANCE_TYPES)}.")
        if ctx.payload.get("remove") is True:
            removed = db.execute(
                "DELETE FROM grievance_routing_rules WHERE fiduciary_id = %s AND grievance_type = %s",
                (fid, grievance_type),
            )
            details = {"grievance_type": grievance_type, "removed": bool(removed)}
        else:
            department = str(require(ctx.payload.get("department"), "department")).strip()
            if not department or len(department) > 100:
                raise ApiError(400, "Bad Request", "department must be 1 to 100 characters.")
            operator_id = require(ctx.payload.get("operator_id"), "operator_id")
            officer = db.one(
                "SELECT id, role FROM operators WHERE id = %s AND fiduciary_id = %s AND status = 'ACTIVE'",
                (operator_id, fid),
            )
            if not officer:
                raise ApiError(404, "Not Found", "Operator not found among this fiduciary's active operators.")
            if not officer_can_handle_grievances(officer["role"], fid):
                raise ApiError(
                    400, "Bad Request", "The officer's role cannot act on grievances (needs grievance:write)."
                )
            db.execute(
                """
                INSERT INTO grievance_routing_rules (fiduciary_id, grievance_type, department, operator_id, updated_by)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (fiduciary_id, grievance_type) DO UPDATE
                    SET department = EXCLUDED.department, operator_id = EXCLUDED.operator_id,
                        updated_by = EXCLUDED.updated_by, updated_at = NOW()
                """,
                (fid, grievance_type, department, str(officer["id"]), ctx.actor_email),
            )
            details = {"grievance_type": grievance_type, "department": department, "operator_id": str(officer["id"])}
        log_event(
            ctx.actor_email or "DPO",
            fid,
            "DPO_CONSOLE",
            None,
            "GRIEVANCE_ROUTING_UPDATED",
            details,
            source_ip=ctx.source_ip,
        )
        return {"success": True, **details}

    def list_grievance_routing(self, ctx: RequestContext) -> list[dict]:
        """GR-07: every category with its department and officer; unrouted
        categories are reported with the DPO fallback."""
        fid = str(require(resolve_fiduciary(ctx), "fiduciary_id"))
        rules = {
            r["grievance_type"]: r
            for r in db.all(
                "SELECT grievance_type, department, operator_id, updated_at FROM grievance_routing_rules"
                " WHERE fiduciary_id = %s",
                (fid,),
            )
        }
        return [
            db.to_jsonable(rules[t]) if t in rules else {"grievance_type": t, "department": "DPO", "operator_id": None}
            for t in sorted(GRIEVANCE_TYPES)
        ]
