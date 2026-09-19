from __future__ import annotations

from .. import db
from ..audit import log_event
from ..context import RequestContext
from .base import Service, require
from .catalog import resolve_fiduciary


class RightsService(Service):
    """Data Principal rights not covered by the consent/grievance flow.

    Implements the DPDP right to nominate (Section 15) and the right to request
    correction of personal data.
    """

    # ── Nomination (Section 15) ──────────────────────────────────────────
    def create_nomination(self, ctx: RequestContext) -> dict:
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        nominator = require(ctx.payload.get("nominating_principal_id"), "nominating_principal_id")
        nominated = require(ctx.payload.get("nominated_principal_id"), "nominated_principal_id")
        row = db.insert_returning(
            """
            INSERT INTO nominations
                (id, fiduciary_id, nominating_principal_id, nominated_principal_id,
                 relationship, valid_from, valid_until, status, created_at, last_updated_at)
            VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, %s, 'ACTIVE', NOW(), NOW())
            RETURNING id
            """,
            (
                fid,
                nominator,
                nominated,
                ctx.payload.get("relationship"),
                ctx.payload.get("valid_from") or None,
                ctx.payload.get("valid_until") or None,
            ),
        )
        nid = str(row["id"])
        log_event(
            nominator,
            fid,
            "APP",
            None,
            "NOMINATION_CREATED",
            {"nomination_id": nid, "nominated_principal_id": nominated},
        )
        return {"success": True, "nomination_id": nid}

    def list_nominations(self, ctx: RequestContext) -> list[dict]:
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        where = ["fiduciary_id = %s"]
        params: list = [fid]
        nominator = ctx.payload.get("nominating_principal_id")
        if nominator:
            where.append("nominating_principal_id = %s")
            params.append(nominator)
        if ctx.payload.get("status"):
            where.append("status = %s")
            params.append(ctx.payload["status"].upper())
        params.append(int(ctx.payload.get("limit") or 50))
        return db.to_jsonable(
            db.all(f"SELECT * FROM nominations WHERE {' AND '.join(where)} ORDER BY created_at DESC LIMIT %s", params)
        )

    def revoke_nomination(self, ctx: RequestContext) -> dict:
        nid = require(ctx.payload.get("nomination_id"), "nomination_id")
        where = ["id = %s"]
        params: list = [nid]
        if ctx.fiduciary_id:
            where.append("fiduciary_id = %s")
            params.append(ctx.fiduciary_id)
        db.execute(
            f"UPDATE nominations SET status = 'REVOKED', last_updated_at = NOW() WHERE {' AND '.join(where)}", params
        )
        return {"success": True, "message": "Nomination revoked."}

    # ── Data correction ──────────────────────────────────────────────────
    def submit_correction(self, ctx: RequestContext) -> dict:
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        user_id = require(ctx.payload.get("user_id"), "user_id")
        row = db.insert_returning(
            """
            INSERT INTO data_correction_requests
                (id, fiduciary_id, user_id, field_name, current_value,
                 requested_value, reason, status, created_at, last_updated_at)
            VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, %s, 'PENDING', NOW(), NOW())
            RETURNING id
            """,
            (
                fid,
                user_id,
                require(ctx.payload.get("field_name"), "field_name"),
                ctx.payload.get("current_value"),
                require(ctx.payload.get("requested_value"), "requested_value"),
                ctx.payload.get("reason"),
            ),
        )
        cid = str(row["id"])
        log_event(
            user_id,
            fid,
            "APP",
            None,
            "CORRECTION_REQUESTED",
            {"correction_id": cid, "field": ctx.payload.get("field_name")},
        )
        return {"success": True, "correction_id": cid}

    def list_corrections(self, ctx: RequestContext) -> list[dict]:
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        where = ["fiduciary_id = %s"]
        params: list = [fid]
        if ctx.payload.get("user_id"):
            where.append("user_id = %s")
            params.append(ctx.payload["user_id"])
        if ctx.payload.get("status"):
            where.append("status = %s")
            params.append(ctx.payload["status"].upper())
        params.append(int(ctx.payload.get("limit") or 50))
        return db.to_jsonable(
            db.all(
                f"SELECT * FROM data_correction_requests WHERE {' AND '.join(where)} ORDER BY created_at DESC LIMIT %s",
                params,
            )
        )

    def update_correction_status(self, ctx: RequestContext) -> dict:
        cid = require(ctx.payload.get("id"), "id")
        status = require(ctx.payload.get("status"), "status").upper()
        db.execute(
            """
            UPDATE data_correction_requests
            SET status = %s, resolution_note = COALESCE(%s, resolution_note),
                resolved_at = CASE WHEN %s IN ('APPROVED', 'REJECTED') THEN NOW() ELSE resolved_at END,
                last_updated_at = NOW()
            WHERE id = %s
            """,
            (status, ctx.payload.get("resolution_note"), status, cid),
        )
        return {"success": True}
