from __future__ import annotations

from typing import Any

from .. import db
from ..audit import log_event
from ..context import RequestContext
from ..errors import ApiError
from .base import Service, page_limit, require, tenant_filter
from .catalog import resolve_fiduciary

VALID_UNITS = {"DAYS", "MONTHS", "YEARS"}
VALID_START_EVENTS = {"CESSATION", "CONSENT", "PURPOSE_START"}
VALID_ACTIONS = {"ERASE", "DE_IDENTIFY"}
# SA-12: a regulatory floor no schedule may undercut. Seven years is the
# statutory minimum for clinical/medical records by sectoral rules (and what the
# ROPA declares for NAS healthcare); shorter periods are rejected outright.
STATUTORY_FLOOR_DAYS = 2557  # 7 years


def retention_duration_days(value: int | None, unit: str | None) -> int:
    """Normalise (value, unit) to whole days. Raises ApiError on invalid input."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise ApiError(400, "Bad Request", "retention_duration_value must be a positive integer.") from None
    unit = str(unit or "DAYS").upper()
    if unit not in VALID_UNITS:
        raise ApiError(400, "Bad Request", f"retention_duration_unit must be one of {sorted(VALID_UNITS)}.")
    if value <= 0:
        raise ApiError(400, "Bad Request", "retention_duration_value must be positive.")
    multiplier = {"DAYS": 1, "MONTHS": 30, "YEARS": 365}[unit]
    return value * multiplier


def applicable_policy(fiduciary_id: str, purpose_id: str | None) -> dict | None:
    """The ACTIVE retention policy governing `purpose_id`: a purpose-specific one
    beats the fiduciary's catch-all (empty applicable_purposes). For "ALL" (a
    whole-account erasure) any policy with a legal basis governs."""
    if purpose_id in (None, "", "ALL"):
        return db.one(
            """
            SELECT * FROM retention_policies
            WHERE fiduciary_id = %s AND status = 'ACTIVE'
            ORDER BY (legal_reference IS NULL) ASC, created_at DESC LIMIT 1
            """,
            (fiduciary_id,),
        )
    return db.one(
        """
        SELECT * FROM retention_policies
        WHERE fiduciary_id = %s AND status = 'ACTIVE'
          AND (applicable_purposes = '[]'::jsonb OR applicable_purposes ? %s)
        ORDER BY (applicable_purposes = '[]'::jsonb) ASC, created_at DESC
        LIMIT 1
        """,
        (fiduciary_id, purpose_id),
    )


def legal_hold_for(fiduciary_id: str, purpose_id: str | None) -> dict | None:
    """CW-11/SA-10: {"legal_reference", "days"} when the law requires keeping the
    data under `purpose_id`, else None. Evaluated when erasure is requested."""
    policy = applicable_policy(fiduciary_id, purpose_id)
    if not policy or not policy.get("legal_reference"):
        return None
    return {
        "legal_reference": policy["legal_reference"],
        "days": retention_duration_days(policy["retention_duration_value"], policy["retention_duration_unit"]),
        "action_at_expiry": policy.get("action_at_expiry") or "ERASE",
    }


class RetentionService(Service):
    """SA-08/SA-10/SA-12: administrator-configurable retention schedules.

    Under DD-03 the retention clock is the schedule configured here — it runs
    from the cessation event and is independent of consent validity. The worker
    sweep (jobs.run_retention_sweep) reads these rows.
    """

    def _fid(self, ctx: RequestContext) -> str:
        return str(require(resolve_fiduciary(ctx), "fiduciary_id"))

    def _apply(
        self,
        payload: dict,
        fid: str,
        policy_id: str | None = None,
    ) -> str:
        name = require(payload.get("name"), "name")
        value = int(require(payload.get("retention_duration_value"), "retention_duration_value"))
        unit = str(payload.get("retention_duration_unit") or "DAYS").upper()
        days = retention_duration_days(value, unit)
        start_event = (
            str(payload.get("retention_start_event") or "CESSATION").replace("_", " ").upper().replace(" ", "_")
        )
        if start_event not in VALID_START_EVENTS:
            raise ApiError(400, "Bad Request", f"retention_start_event must be one of {sorted(VALID_START_EVENTS)}.")
        action = str(payload.get("action_at_expiry") or "ERASE").replace("-", "_").upper()
        if action not in VALID_ACTIONS:
            raise ApiError(400, "Bad Request", f"action_at_expiry must be one of {sorted(VALID_ACTIONS)}.")
        # SA-12: never admit a schedule beneath the statutory floor for clinical
        # records. An exemption (SA-10) must cite the retention rule relied on.
        if days < STATUTORY_FLOOR_DAYS:
            raise ApiError(
                400,
                "Bad Request",
                f"Retention of {days} days is below the {STATUTORY_FLOOR_DAYS}-day statutory floor for health records. "
                "If a legal exemption applies, cite it in legal_reference.",
            )
        legal_reference = payload.get("legal_reference")
        if not legal_reference and action != "ERASE":
            raise ApiError(
                400, "Bad Request", "action_at_expiry other than ERASE requires a legal_reference exemption."
            )
        if policy_id:
            db.execute(
                """
                UPDATE retention_policies SET name = %s, description = %s, applicable_purposes = %s,
                       applicable_data_categories = %s, retention_duration_value = %s, retention_duration_unit = %s,
                       retention_start_event = %s, action_at_expiry = %s, legal_reference = %s, status = %s,
                       updated_at = NOW()
                WHERE id = %s
                """,
                (
                    name,
                    payload.get("description"),
                    db.as_jsonb(payload.get("applicable_purposes") or []),
                    db.as_jsonb(payload.get("applicable_data_categories") or []),
                    value,
                    unit,
                    start_event,
                    action,
                    legal_reference,
                    str(payload.get("status") or "ACTIVE").upper(),
                    policy_id,
                ),
            )
            return policy_id
        row = db.insert_returning(
            """
            INSERT INTO retention_policies
                (fiduciary_id, name, description, applicable_purposes, applicable_data_categories,
                 retention_duration_value, retention_duration_unit, retention_start_event,
                 action_at_expiry, legal_reference, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                fid,
                name,
                payload.get("description"),
                db.as_jsonb(payload.get("applicable_purposes") or []),
                db.as_jsonb(payload.get("applicable_data_categories") or []),
                value,
                unit,
                start_event,
                action,
                legal_reference,
                str(payload.get("status") or "ACTIVE").upper(),
            ),
        )
        return str(row["id"])

    def create_retention_policy(self, ctx: RequestContext) -> dict:
        fid = self._fid(ctx)
        policy_id = self._apply(ctx.payload, fid)
        log_event(
            ctx.actor_email or "DPO",
            fid,
            "DPO_CONSOLE",
            None,
            "RETENTION_POLICY_CREATED",
            {"policy_id": policy_id, "name": ctx.payload.get("name")},
            source_ip=ctx.source_ip,
        )
        return {"success": True, "policy_id": policy_id}

    def set_retention_policy(self, ctx: RequestContext) -> dict:
        """SA-08 alias for create_retention_policy (upsert when a policy_id is given)."""
        if ctx.payload.get("policy_id"):
            return self.update_retention_policy(ctx)
        return self.create_retention_policy(ctx)

    def update_retention_policy(self, ctx: RequestContext) -> dict:
        fid = self._fid(ctx)
        policy_id = require(ctx.payload.get("policy_id"), "policy_id")
        row = db.one(
            "SELECT id FROM retention_policies WHERE id = %s AND fiduciary_id = %s",
            (policy_id, fid),
        )
        if not row:
            raise ApiError(404, "Not Found", "Retention policy not found for this fiduciary.")
        self._apply(ctx.payload, fid, policy_id=policy_id)
        log_event(
            ctx.actor_email or "DPO",
            fid,
            "DPO_CONSOLE",
            None,
            "RETENTION_POLICY_UPDATED",
            {"policy_id": policy_id},
            source_ip=ctx.source_ip,
        )
        return {"success": True, "policy_id": policy_id}

    def get_retention_policy(self, ctx: RequestContext) -> dict:
        fid = self._fid(ctx)
        policy_id = require(ctx.payload.get("policy_id"), "policy_id")
        row = db.one(
            "SELECT * FROM retention_policies WHERE id = %s AND fiduciary_id = %s",
            (policy_id, fid),
        )
        if not row:
            raise ApiError(404, "Not Found", "Retention policy not found.")
        return db.to_jsonable(row)

    def list_retention_policies(self, ctx: RequestContext) -> list[dict]:
        page, limit = page_limit(ctx.payload, 50)
        where = ["fiduciary_id = %s"]
        params: list[Any] = [self._fid(ctx)]
        if ctx.payload.get("status"):
            where.append("status = %s")
            params.append(ctx.payload["status"].upper())
        params.extend([limit, (page - 1) * limit])
        return db.to_jsonable(
            db.all(
                f"SELECT * FROM retention_policies WHERE {' AND '.join(where)} ORDER BY created_at DESC LIMIT %s OFFSET %s",
                params,
            )
        )

    def delete_retention_policy(self, ctx: RequestContext) -> dict:
        fid = self._fid(ctx)
        policy_id = require(ctx.payload.get("policy_id"), "policy_id")
        db.execute(
            "UPDATE retention_policies SET status = 'INACTIVE', updated_at = NOW() WHERE id = %s AND fiduciary_id = %s",
            (policy_id, fid),
        )
        return {"success": True, "policy_id": policy_id}

    def validate_completeness(self, ctx: RequestContext) -> dict:
        """SA-12: confirm a configured schedule meets the regulatory floor."""
        policy_id = require(
            ctx.payload.get("policy_id") or ctx.payload.get("id"),
            "policy_id",
        )
        scope, scope_params = tenant_filter(ctx)
        row = db.one(f"SELECT * FROM retention_policies WHERE id = %s{scope}", (policy_id, *scope_params))
        if not row:
            raise ApiError(404, "Not Found", "Retention policy not found.")
        days = retention_duration_days(row["retention_duration_value"], row["retention_duration_unit"])
        missing = []
        if not row.get("name"):
            missing.append("name")
        if not row.get("applicable_data_categories") and not row.get("applicable_purposes"):
            missing.append("applicable_purposes/applicable_data_categories")
        complete = not missing and days >= STATUTORY_FLOOR_DAYS
        return {
            "is_complete": complete,
            "complete": complete,
            "missing": missing,
            "missing_fields": missing,
            "retention_days": days,
            "statutory_floor_days": STATUTORY_FLOOR_DAYS,
        }
