from __future__ import annotations

from .. import db
from ..context import RequestContext
from ..errors import ApiError
from .base import Service, page_limit, require
from .catalog import resolve_fiduciary


class ComplianceService(Service):
    def list_purge_requests(self, ctx: RequestContext) -> list[dict]:
        page, limit = page_limit(ctx.payload, 50)
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        where = ["fiduciary_id = %s"]
        params = [fid]
        if ctx.payload.get("status"):
            where.append("status = %s")
            params.append(ctx.payload["status"])
        params.extend([limit, (page - 1) * limit])
        return db.to_jsonable(
            db.all(
                f"SELECT * FROM purge_requests WHERE {' AND '.join(where)} ORDER BY initiated_at DESC LIMIT %s OFFSET %s",
                params,
            )
        )

    def get_purge_request(self, ctx: RequestContext) -> dict:
        row = db.one("SELECT * FROM purge_requests WHERE id = %s", (require(ctx.payload.get("id"), "id"),))
        if not row:
            raise ApiError(404, "Not Found", "Purge request not found.")
        return db.to_jsonable(row)

    def update_purge_status(self, ctx: RequestContext) -> dict:
        db.execute(
            "UPDATE purge_requests SET status = %s, details = COALESCE(%s, details), last_updated_at = NOW() WHERE id = %s",
            (
                require(ctx.payload.get("status"), "status"),
                ctx.payload.get("details"),
                require(ctx.payload.get("id"), "id"),
            ),
        )
        return {"success": True}

    def assign_purge_request(self, ctx: RequestContext) -> dict:
        db.execute(
            "UPDATE purge_requests SET assigned_operator_id = %s, last_updated_at = NOW() WHERE id = %s",
            (require(ctx.payload.get("operator_id"), "operator_id"), require(ctx.payload.get("id"), "id")),
        )
        return {"success": True}


class GrievanceService(Service):
    def submit_grievance(self, ctx: RequestContext) -> dict:
        row = db.insert_returning(
            """
            INSERT INTO grievances
                (id, user_id, fiduciary_id, type, subject, description,
                 submission_timestamp, status, communication_log, attachments, due_date)
            VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, NOW(), 'NEW', %s, %s, NOW() + INTERVAL '30 days')
            RETURNING id
            """,
            (
                require(ctx.payload.get("user_id"), "user_id"),
                require(resolve_fiduciary(ctx), "fiduciary_id"),
                require(ctx.payload.get("type"), "type"),
                require(ctx.payload.get("subject"), "subject"),
                require(ctx.payload.get("description"), "description"),
                db.as_jsonb([]),
                db.as_jsonb(ctx.payload.get("attachments") or []),
            ),
        )
        return {"success": True, "grievance_id": str(row["id"])}

    def get_grievance(self, ctx: RequestContext) -> dict:
        gid = ctx.payload.get("grievance_id") or ctx.payload.get("id")
        row = db.one("SELECT * FROM grievances WHERE id = %s", (require(gid, "grievance_id"),))
        if not row:
            raise ApiError(404, "Not Found", "Grievance not found.")
        return db.to_jsonable(row)

    def list_grievances(self, ctx: RequestContext) -> list[dict]:
        page, limit = page_limit(ctx.payload, 50)
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        where = ["fiduciary_id = %s"]
        params = [fid]
        if ctx.payload.get("status"):
            where.append("status = %s")
            params.append(ctx.payload["status"])
        params.extend([limit, (page - 1) * limit])
        return db.to_jsonable(
            db.all(
                f"SELECT * FROM grievances WHERE {' AND '.join(where)} ORDER BY submission_timestamp DESC LIMIT %s OFFSET %s",
                params,
            )
        )

    def list_user_grievances(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(
            db.all(
                "SELECT * FROM grievances WHERE fiduciary_id = %s AND user_id = %s ORDER BY submission_timestamp DESC",
                (require(resolve_fiduciary(ctx), "fiduciary_id"), require(ctx.payload.get("user_id"), "user_id")),
            )
        )

    def update_grievance_status(self, ctx: RequestContext) -> dict:
        gid = ctx.payload.get("grievance_id") or ctx.payload.get("id")
        db.execute(
            "UPDATE grievances SET status = %s, resolution_details = COALESCE(%s, resolution_details), resolution_timestamp = CASE WHEN %s IN ('RESOLVED','CLOSED') THEN NOW() ELSE resolution_timestamp END, last_updated_at = NOW() WHERE id = %s",
            (
                require(ctx.payload.get("status"), "status"),
                ctx.payload.get("resolution_details"),
                ctx.payload.get("status"),
                require(gid, "grievance_id"),
            ),
        )
        return {"success": True}

    def assign_grievance(self, ctx: RequestContext) -> dict:
        db.execute(
            "UPDATE grievances SET assigned_dpo_user_id = %s, status = 'IN_PROGRESS', last_updated_at = NOW() WHERE id = %s",
            (
                require(ctx.payload.get("operator_id"), "operator_id"),
                require(ctx.payload.get("grievance_id"), "grievance_id"),
            ),
        )
        return {"success": True}

    def add_grievance_communication(self, ctx: RequestContext) -> dict:
        return self.update_grievance_status(ctx)


class BreachService(Service):
    def report_breach(self, ctx: RequestContext) -> dict:
        row = db.insert_returning(
            """
            INSERT INTO breach_incidents
                (id, fiduciary_id, title, description, detected_at, affected_purpose_id,
                 affected_data_categories, actionable_steps, severity, status,
                 affected_principal_count, created_by_user_id, notification_type)
            VALUES (uuid_generate_v4(), %s, %s, %s, COALESCE(%s::timestamptz, NOW()), %s, %s,
                    %s, COALESCE(%s, 'MEDIUM'), 'OPEN', %s, %s, %s)
            RETURNING id
            """,
            (
                require(resolve_fiduciary(ctx), "fiduciary_id"),
                require(ctx.payload.get("title"), "title"),
                require(ctx.payload.get("description"), "description"),
                ctx.payload.get("detected_at"),
                ctx.payload.get("affected_purpose_id"),
                db.as_jsonb(ctx.payload.get("affected_data_categories") or []),
                require(ctx.payload.get("actionable_steps"), "actionable_steps"),
                ctx.payload.get("severity"),
                int(ctx.payload.get("affected_principal_count") or 0),
                None,
                ctx.payload.get("notification_type", "BREACH_NOTIFICATION"),
            ),
        )
        return {"success": True, "breach_id": str(row["id"])}

    def list_breaches(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(
            db.all(
                "SELECT * FROM breach_incidents WHERE fiduciary_id = %s ORDER BY reported_at DESC LIMIT %s",
                (require(resolve_fiduciary(ctx), "fiduciary_id"), int(ctx.payload.get("limit") or 50)),
            )
        )

    def get_breach(self, ctx: RequestContext) -> dict:
        row = db.one("SELECT * FROM breach_incidents WHERE id = %s", (require(ctx.payload.get("id"), "id"),))
        if not row:
            raise ApiError(404, "Not Found", "Breach not found.")
        return db.to_jsonable(row)

    def update_breach_status(self, ctx: RequestContext) -> dict:
        db.execute(
            "UPDATE breach_incidents SET status = %s, resolution_notes = COALESCE(%s, resolution_notes), last_updated_at = NOW() WHERE id = %s",
            (
                require(ctx.payload.get("status"), "status"),
                ctx.payload.get("resolution_notes"),
                require(ctx.payload.get("id"), "id"),
            ),
        )
        return {"success": True}

    def download_breach_report(self, ctx: RequestContext) -> dict:
        return self.get_breach(ctx)
