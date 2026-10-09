from __future__ import annotations

from datetime import UTC, datetime

from .. import db
from ..audit import log_event
from ..context import RequestContext
from ..errors import ApiError
from .base import Service, bind_principal_field, principal_list_filter, require, tenant_filter
from .catalog import resolve_fiduciary


def _parse_ts(value) -> datetime | None:
    """Normalise a (possibly naive/ISO) timestamp to an aware datetime, or None."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return None


class RightsService(Service):
    """Data Principal rights not covered by the consent/grievance flow.

    Implements the DPDP right to nominate (Section 15) and the right to request
    correction of personal data.
    """

    # ── Nomination (Section 15) ──────────────────────────────────────────
    def create_nomination(self, ctx: RequestContext) -> dict:
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        bind_principal_field(ctx, "nominating_principal_id")
        nominator = require(ctx.payload.get("nominating_principal_id"), "nominating_principal_id")
        nominated = require(ctx.payload.get("nominated_principal_id"), "nominated_principal_id")
        row = db.insert_returning(
            """
            INSERT INTO nominations
                (id, fiduciary_id, nominating_principal_id, nominated_principal_id,
                 relationship, valid_from, valid_until, status, created_at, last_updated_at)
            VALUES (uuid_generate_v4(), %s, %s, %s, %s, COALESCE(%s, NOW()), %s, %s, NOW(), NOW())
            RETURNING id
            """,
            (
                fid,
                nominator,
                nominated,
                ctx.payload.get("relationship"),
                # P6-07: a caller-supplied valid_from (a future effective date) is
                # honoured instead of being silently discarded; the clone-safety
                # behaviour when it is absent is the DEFAULT NOW() that P5-06
                # restored.
                ctx.payload.get("valid_from") or None,
                ctx.payload.get("valid_until") or None,
                # P6-07: a nomination whose valid_from is still in the future is
                # stored PENDING, never ACTIVE.
                "PENDING"
                if _parse_ts(ctx.payload.get("valid_from")) and _parse_ts(ctx.payload.get("valid_from")) > datetime.now(UTC)
                else "ACTIVE",
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
        nominator = principal_list_filter(ctx, "nominating_principal_id")
        if nominator:
            where.append("nominating_principal_id = %s")
            params.append(nominator)
        # P6-07: the EFFECTIVE status derives from the dates, not the stored
        # literal. A nomination dated 2030 is PENDING (not active) until
        # valid_from; one whose valid_until has passed is EXPIRED. Filtering by
        # status applies to the effective status so callers can list "active
        # today" without guessing.
        status_filter = ctx.payload.get("status")
        if status_filter:
            status_filter = str(status_filter).upper()
            where.append(
                """CASE
                     WHEN valid_from IS NOT NULL AND valid_from > NOW() THEN 'PENDING'
                     WHEN valid_until IS NOT NULL AND valid_until < NOW() THEN 'EXPIRED'
                     ELSE status END = %s"""
            )
            params.append(status_filter)
        params.append(int(ctx.payload.get("limit") or 50))
        rows = db.all(f"SELECT * FROM nominations WHERE {' AND '.join(where)} ORDER BY created_at DESC LIMIT %s", params)
        # P6-07: compute the effective status in Python so the contract is explicit
        # and testable — never trust a stored literal a future date makes stale.
        now = datetime.now(UTC)
        out = []
        for row in rows:
            item = db.to_jsonable(row)
            from_ = item.get("valid_from")
            until = item.get("valid_until")
            effective = item.get("status")
            if until and _parse_ts(until) < now:
                effective = "EXPIRED"
            elif from_ and _parse_ts(from_) > now:
                effective = "PENDING"
            item["status"] = effective
            item["effective_status"] = effective
            out.append(item)
        return out

    def revoke_nomination(self, ctx: RequestContext) -> dict:
        nid = require(ctx.payload.get("nomination_id"), "nomination_id")
        where = ["id = %s"]
        params: list = [nid]
        if ctx.fiduciary_id:
            where.append("fiduciary_id = %s")
            params.append(ctx.fiduciary_id)
        if ctx.auth_via_principal_jwt:
            row = db.one(
                f"SELECT nominating_principal_id FROM nominations WHERE {' AND '.join(where)}",
                params,
            )
            if not row:
                raise ApiError(404, "Not Found", "Nomination not found.")
            if str(row["nominating_principal_id"]) != ctx.principal_user_id:
                raise ApiError(403, "Forbidden", "You may only revoke your own nominations.")
        updated = db.execute(
            f"UPDATE nominations SET status = 'REVOKED', last_updated_at = NOW() WHERE {' AND '.join(where)}", params
        )
        # SEC-12: a revoke that did not happen is not reported as done.
        if updated == 0:
            raise ApiError(404, "Not Found", "Nomination not found.")
        return {"success": True, "message": "Nomination revoked."}

    # ── Data correction ──────────────────────────────────────────────────
    def submit_correction(self, ctx: RequestContext) -> dict:
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        bind_principal_field(ctx, "user_id")
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
        user_id = principal_list_filter(ctx, "user_id")
        if user_id:
            where.append("user_id = %s")
            params.append(user_id)
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
