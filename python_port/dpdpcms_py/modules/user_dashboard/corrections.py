from __future__ import annotations

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import bind_principal_field, principal_list_filter, require, tenant_filter
from dpdpcms_py.modules.administration.api import resolve_fiduciary
from dpdpcms_py.modules.audit_logging.ledger import log_event


class CorrectionHandlers:
    # ── Data correction ──────────────────────────────────────────────────
    def submit_correction(self, ctx: RequestContext) -> dict:
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        bind_principal_field(ctx, "user_id")
        user_id = require(ctx.payload.get("user_id"), "user_id")
        row = db.insert_returning(
            f"""
            INSERT INTO data_correction_requests
                (id, fiduciary_id, user_id_enc, user_id_hmac, field_name, current_value,
                 requested_value, reason, status, created_at, last_updated_at)
            VALUES (uuid_generate_v4(), %s, {pii.PID_VALUES}, %s, %s, %s, %s, 'PENDING', NOW(), NOW())
            RETURNING id
            """,
            (
                fid,
                *pii.pid_params(str(user_id)),
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
        user_id = principal_list_filter(ctx, "user_id")
        if user_id:
            where.append(pii.match_sql("user_id"))
            params.extend(pii.hmac_params(str(user_id)))
        if ctx.payload.get("status"):
            where.append("status = %s")
            params.append(ctx.payload["status"].upper())
        params.append(int(ctx.payload.get("limit") or 50))
        rows = db.all(
            f"SELECT *, {pii.dec_sql('user_id_enc')} AS user_id FROM data_correction_requests"
            f" WHERE {' AND '.join(where)} ORDER BY created_at DESC LIMIT %s",
            [*db.bind_key(), *params],
        )
        return [pii.principal_row(ctx, row, "user_id") for row in rows]

    def update_correction_status(self, ctx: RequestContext) -> dict:
        cid = require(ctx.payload.get("id"), "id")
        status = require(ctx.payload.get("status"), "status").upper()
        scope, scope_params = tenant_filter(ctx)
        updated = db.execute(
            f"""
            UPDATE data_correction_requests
            SET status = %s, resolution_note = COALESCE(%s, resolution_note),
                resolved_at = CASE WHEN %s IN ('APPROVED', 'REJECTED') THEN NOW() ELSE resolved_at END,
                last_updated_at = NOW()
            WHERE id = %s{scope}
            """,
            (status, ctx.payload.get("resolution_note"), status, cid, *scope_params),
        )
        if updated == 0:
            raise ApiError(404, "Not Found", "Correction request not found.")
        return {"success": True}
