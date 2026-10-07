from __future__ import annotations

import csv
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import db
from .audit import log_event
from .config import settings
from .services.lifecycle import close_purpose_exec

log = logging.getLogger("dpdpcms.jobs")


def _claim_pending_purges(fiduciary_id: str, purpose_id: str, trigger: str) -> bool:
    """True when no non-terminal purge request already covers (fid, purpose, trigger)."""
    row = db.one(
        """
        SELECT 1 FROM purge_requests
        WHERE fiduciary_id = %s AND purpose_id = %s AND trigger_event = %s
          AND status IN ('PENDING', 'IN_PROGRESS')
        LIMIT 1
        """,
        (fiduciary_id, purpose_id, trigger),
    )
    return row is None


def close_due_time_bound_purposes() -> dict[str, int]:
    """PL-01: a TIME_BOUND purpose whose consent window has elapsed is closed.

    Closing reuses the full closure pipeline (purge requests, principal
    notifications, fiduciary alert, webhook, audit) — the same path as the DPO
    closing a purpose by hand through close_purpose.
    """
    due = db.all(
        """
        SELECT fiduciary_id, purpose_id, opened_at, consent_expiry_days
        FROM purpose_lifecycle
        WHERE duration_type = 'TIME_BOUND' AND state = 'OPEN' AND consent_expiry_days IS NOT NULL
          AND opened_at + make_interval(days => consent_expiry_days) <= NOW()
        ORDER BY opened_at
        LIMIT %s
        """,
        (settings.worker_batch_size,),
    )
    closed = 0
    for row in due:
        fid = str(row["fiduciary_id"])
        purpose_id = str(row["purpose_id"])
        try:
            close_purpose_exec(
                fiduciary_id=fid,
                purpose_id=purpose_id,
                reason="Time-bound purpose reached its consent_expiry_days under the purpose lifecycle (PL-01).",
                deidentification_action="ERASE",
                closed_by=None,
            )
            closed += 1
        except Exception:
            log.exception("Time-bound closure failed for %s/%s", fid, purpose_id)
    return {"closed": closed, "scanned": len(due)}


def escalate_stale_alerts() -> dict[str, int]:
    """NT-09: escalate alerts nobody has acknowledged within the SLA window."""
    escalated = db.execute(
        """
        UPDATE alerts
        SET status = 'ESCALATED', escalated_at = NOW()
        WHERE status = 'PENDING' AND requires_action IS TRUE
          AND created_at < NOW() - make_interval(hours => %s)
        """,
        (settings.alert_escalation_hours,),
    )
    return {"escalated": escalated or 0}


def escalate_overdue_grievances() -> dict[str, int]:
    """UD-12 / GR-09: auto-escalate grievances past their SLA due date."""
    # GR-09: escalate once the SLA due date plus the configured grace period
    # (GRIEVANCE_ESCALATION_HOURS) has passed. The UPDATE ... RETURNING is the
    # claim, so two workers can never escalate the same grievance twice (UD-12).
    rows = db.all(
        """
        UPDATE grievances SET status = 'ESCALATED', escalated_at = NOW(), last_updated_at = NOW()
        WHERE id IN (
            SELECT id FROM grievances
            WHERE status IN ('NEW', 'IN_PROGRESS') AND due_date IS NOT NULL
              AND due_date + make_interval(hours => %s) < NOW()
            ORDER BY due_date
            LIMIT %s
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id, user_id, fiduciary_id
        """,
        (settings.grievance_escalation_hours, settings.worker_batch_size),
    )
    count = 0
    for row in rows:
        gid = str(row["id"])
        fid = str(row["fiduciary_id"])
        db.execute(
            """
            INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type)
            VALUES ('PRINCIPAL', %s, %s, 'GRIEVANCE_ESCALATED')
            """,
            (str(row["user_id"]), fid),
        )
        log_event(str(row["user_id"]), fid, "APP", None, "GRIEVANCE_ESCALATED", {"grievance_id": gid})
        count += 1
    return {"escalated": count}


def _retention_for(fiduciary_id: str, purpose_id: str) -> tuple[int | None, str | None]:
    """(retention_period_days, retention_start_event) for a closed purpose.

    DD-03: the administrator-configured retention policy is the primary clock.
    Falls back to the fiduciary's active ROPA when no policy applies.
    """
    row = db.one(
        """
        SELECT retention_duration_value, retention_duration_unit, retention_start_event, legal_reference
        FROM retention_policies
        WHERE fiduciary_id = %s AND status = 'ACTIVE'
          AND (applicable_purposes = '[]'::jsonb OR applicable_purposes ? %s)
        ORDER BY (applicable_purposes = '[]'::jsonb) ASC, created_at DESC
        LIMIT 1
        """,
        (fiduciary_id, purpose_id),
    )
    if row:
        days = int(row["retention_duration_value"] or 0) * {
            "DAYS": 1,
            "MONTHS": 30,
            "YEARS": 365,
        }.get(str(row["retention_duration_unit"] or "DAYS").upper(), 1)
        return (days or None, row.get("retention_start_event"))
    row = db.one(
        """
        SELECT retention_period_days, retention_start_event
        FROM ropa_entries
        WHERE fiduciary_id = %s AND source_purpose_id = %s AND status = 'active'
        ORDER BY (retention_start_event = 'CESSATION') DESC, updated_at DESC
        LIMIT 1
        """,
        (fiduciary_id, purpose_id),
    )
    if not row:
        return None, None
    return (row.get("retention_period_days"), row.get("retention_start_event"))


def _cessation_for(fiduciary_id: str, purpose_id: str) -> datetime | None:
    """Latest moment processing ceased for a purpose: purpose closure, else last withdrawal."""
    closed = db.one(
        "SELECT closed_at FROM purpose_lifecycle WHERE fiduciary_id = %s AND purpose_id = %s AND state = 'CLOSED'",
        (fiduciary_id, purpose_id),
    )
    if closed and closed.get("closed_at"):
        return closed["closed_at"]
    row = db.one(
        """
        SELECT MAX(cr.last_updated_at) AS cessation
        FROM consent_records cr,
             LATERAL jsonb_array_elements(cr.data_point_consents) AS p
        WHERE cr.fiduciary_id = %s
          AND p ->> 'data_point_id' = %s
          AND (p ->> 'consent_granted' = 'false' OR lower(p ->> 'status') = 'withdrawn')
        """,
        (fiduciary_id, purpose_id),
    )
    return row["cessation"] if row else None


def _expiry_action(fiduciary_id: str, purpose_id: str) -> str:
    """PL-03: ERASE or DE_IDENTIFY for a purge raised at retention expiry — the
    retention policy's action_at_expiry, else the action chosen at closure."""
    from .services.retention import applicable_policy

    policy = applicable_policy(fiduciary_id, purpose_id)
    if policy and policy.get("action_at_expiry"):
        return str(policy["action_at_expiry"]).upper()
    row = db.one(
        "SELECT deidentification_action FROM purpose_lifecycle WHERE fiduciary_id = %s AND purpose_id = %s",
        (fiduciary_id, purpose_id),
    )
    return str((row or {}).get("deidentification_action") or "ERASE").upper()


def flag_overdue_purges() -> dict[str, int]:
    """SA-09: a purge the CMS orchestrated must be confirmed done. Requests still
    open past PURGE_COMPLETION_SLA_DAYS (and not under legal hold) are flagged to
    the DPO once, so an unconfirmed deletion never passes silently."""
    rows = db.all(
        """
        UPDATE purge_requests SET overdue_notified_at = NOW()
        WHERE id IN (
            SELECT id FROM purge_requests
            WHERE status IN ('PENDING', 'IN_PROGRESS', 'PURGE_IN_PROGRESS')
              AND overdue_notified_at IS NULL
              AND initiated_at < NOW() - make_interval(days => %s)
            LIMIT %s
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id, fiduciary_id, purpose_id
        """,
        (settings.purge_completion_sla_days, settings.worker_batch_size),
    )
    for row in rows:
        fid = str(row["fiduciary_id"])
        db.execute(
            "INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type) VALUES ('DPO', %s, %s, 'PURGE_OVERDUE')",
            (_dpo_recipient(fid), fid),
        )
        log_event(
            "SYSTEM",
            fid,
            "SYSTEM",
            None,
            "PURGE_OVERDUE",
            {"purge_request_id": str(row["id"]), "purpose_id": row["purpose_id"]},
        )
    return {"flagged": len(rows)}


def release_expired_legal_holds() -> dict[str, int]:
    """CW-11: a legal hold lasts for the retention period it cites; once that
    ends the request becomes an ordinary pending purge."""
    released = db.execute(
        """
        UPDATE purge_requests SET status = 'PENDING', last_updated_at = NOW(),
               details = COALESCE(details || ' ', '') || '[legal hold expired]'
        WHERE status = 'LEGAL_HOLD_APPLIED' AND hold_until IS NOT NULL AND hold_until < NOW()
        """
    )
    return {"released": released or 0}


def prune_revoked_tokens() -> dict[str, int]:
    """SA-05: a revoked token only needs remembering until it would have expired anyway."""
    return {"pruned": db.execute("DELETE FROM revoked_tokens WHERE expires_at < NOW()") or 0}


def expire_lapsed_api_keys() -> dict[str, int]:
    """SEC-07: mark keys whose expires_at has passed as EXPIRED so the listing
    and the enforced behaviour (security.api_key_valid) always agree.

    Enforcement already rejects an expired key at authenticate time; until this
    sweep runs the console still shows such a key as ACTIVE, which is exactly
    the mismatch the finding called out.
    """
    updated = db.execute(
        "UPDATE api_keys SET status = 'EXPIRED', last_used_at = last_used_at"
        " WHERE status = 'ACTIVE' AND expires_at IS NOT NULL AND expires_at < NOW()"
    )
    return {"expired": updated or 0}


def prune_sso_nonces() -> dict[str, int]:
    """SEC-14: drop SSO login nonces past the token lifetime; a nonce can never
    be presented again once its id_token would have expired anyway."""
    return {"pruned": db.execute("DELETE FROM sso_login_nonces WHERE expires_at < NOW()") or 0}


def prune_old_webhook_deliveries(days: int | None = None) -> dict[str, int]:
    """SEC-13 / P5-07: retention on webhook_deliveries.

    Terminal rows (dispatched, failed after the retry limit, or skipped with no
    configured webhook) are removed once they are older than `days`. SEC-13 made
    the queue stop holding plaintext OTP codes (rows are payload->>'otp
    encrypted), so a long retention no longer preserves secrets in the clear.
    P5-07: the delivery table is the channel of record for consent events and
    OTP dispatch, so the default honours the Rule 6(1)(e) one-year floor
    (WEBHOOK_DELIVERY_RETENTION_DAYS) rather than a hard-coded 30.
    """
    days = days or settings.webhook_delivery_retention_days
    pruned = (
        db.execute(
            "DELETE FROM webhook_deliveries WHERE status IN ('DISPATCHED', 'FAILED', 'SKIPPED')"
            " AND created_at < NOW() - make_interval(days => %s)",
            (int(days),),
        )
        or 0
    )
    return {"pruned": pruned}


def _dpo_recipient(fiduciary_id: str) -> str:
    row = db.one(
        "SELECT id FROM operators WHERE fiduciary_id = %s AND role = 'DPO' AND status = 'ACTIVE' ORDER BY created_at LIMIT 1",
        (fiduciary_id,),
    )
    return str(row["id"]) if row else fiduciary_id


def run_retention_sweep() -> dict[str, int]:
    """PL-04 / SA-09 / SA-11: run the retention clock from cessation, independently of
    consent state, and warn administrators 48 hours before a scheduled deletion."""
    purposes = db.all("SELECT DISTINCT purpose_id, fiduciary_id FROM purpose_lifecycle WHERE state = 'CLOSED'")
    created = 0
    notices = 0
    for row in purposes:
        fid = str(row["fiduciary_id"])
        purpose_id = str(row["purpose_id"])
        retention_days, _start = _retention_for(fid, purpose_id)
        if not retention_days:
            continue
        cessation = _cessation_for(fid, purpose_id)
        if not cessation:
            cessation = datetime.now(UTC)
        due = cessation + timedelta(days=int(retention_days))
        window = (due - datetime.now(UTC)).total_seconds() / 3600.0
        if window <= 0:
            if _claim_pending_purges(fid, purpose_id, "RetentionPolicyExpiry"):
                rowcount = db.execute(
                    """
                    INSERT INTO purge_requests (user_id, fiduciary_id, purpose_id, trigger_event, details, action)
                    SELECT DISTINCT cr.user_id, cr.fiduciary_id, %s, 'RetentionPolicyExpiry', %s, %s
                    FROM consent_records cr,
                         LATERAL jsonb_array_elements(cr.data_point_consents) AS p
                    WHERE cr.fiduciary_id = %s AND p ->> 'data_point_id' = %s
                      AND NOT EXISTS (
                            SELECT 1 FROM purge_requests pr
                            WHERE pr.user_id = cr.user_id
                              AND pr.fiduciary_id = cr.fiduciary_id
                              AND pr.purpose_id = %s
                              AND pr.trigger_event = 'RetentionPolicyExpiry'
                              AND pr.status IN ('PENDING', 'IN_PROGRESS')
                          )
                    """,
                    (
                        purpose_id,
                        f"Retention period of {retention_days} days elapsed from cessation {due.isoformat()} (PL-04).",
                        _expiry_action(fid, purpose_id),
                        fid,
                        purpose_id,
                        purpose_id,
                    ),
                )
                created += rowcount or 0
                db.execute(
                    """
                    INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type)
                    VALUES ('DPO', %s, %s, 'PURGE_EXECUTED')
                    """,
                    (_dpo_recipient(fid), fid),
                )
        elif window <= float(settings.purge_notice_hours):
            existing = db.one(
                """
                SELECT 1 FROM notifications
                WHERE fiduciary_id = %s AND notification_type = 'PURGE_SCHEDULED'
                  AND recipient_id = %s AND created_at > NOW() - INTERVAL '24 hours'
                LIMIT 1
                """,
                (fid, _dpo_recipient(fid)),
            )
            if not existing:
                db.execute(
                    """
                    INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type)
                    VALUES ('DPO', %s, %s, 'PURGE_SCHEDULED')
                    """,
                    (_dpo_recipient(fid), fid),
                )
                notices += 1
                log_event(
                    "SYSTEM",
                    fid,
                    "SYSTEM",
                    None,
                    "PURGE_SCHEDULED",
                    {"purpose_id": purpose_id, "due": due.isoformat(), "notice_hours": settings.purge_notice_hours},
                )
    return {"purge_requests_created": created, "admin_notices": notices}


_CSV_SUBSCRIPTIONS: dict[str, tuple[str, str, str]] = {
    # subtype -> (table, default_columns, date_column)
    "CONSENT": ("consent_records", "id,user_id,policy_id,policy_version,consent_status_general,timestamp", "timestamp"),
    "PRINCIPAL": (
        "data_principal",
        "user_id,fiduciary_id,last_consent_mechanism,age_category,created_at",
        "created_at",
    ),
    "GRIEVANCE": ("grievances", "id,user_id,type,subject,status,submission_timestamp", "submission_timestamp"),
    "AUDIT": ("audit_logs", "id,fiduciary_id,timestamp,user_id,service_type,audit_action,context_details", "timestamp"),
}


def execute_queued_jobs() -> dict[str, int]:
    """LG-07: run PENDING jobs — EXPORT subtypes write CSV files; CES runs the
    time-bound purpose closure for the fiduciary. This replaces the queue that
    previously never executed."""
    rows = db.all(
        """
        SELECT id, fiduciary_id, job_type, subtype, start_date, end_date, input_payload
        FROM jobs WHERE status = 'PENDING' ORDER BY created_at LIMIT %s
        """,
        (settings.worker_batch_size,),
    )
    completed = failed = 0
    for row in rows:
        job_id = str(row["id"])
        if (
            db.execute(
                "UPDATE jobs SET status = 'RUNNING', started_at = NOW() WHERE id = %s AND status = 'PENDING'",
                (job_id,),
            )
            != 1
        ):
            continue
        job_type = str(row["job_type"] or "").upper()
        subtype = str(row["subtype"] or "").upper()
        try:
            if job_type == "CES":
                close_due_time_bound_purposes()
                db.execute("UPDATE jobs SET status = 'COMPLETED', completed_at = NOW() WHERE id = %s", (job_id,))
                completed += 1
                continue
            if job_type == "EXPORT" and subtype in _CSV_SUBSCRIPTIONS:
                path = _write_export(row)
                db.execute(
                    "UPDATE jobs SET status = 'COMPLETED', completed_at = NOW(), output_file_path = %s WHERE id = %s",
                    (str(path), job_id),
                )
                completed += 1
                continue
            db.execute(
                "UPDATE jobs SET status = 'FAILED', completed_at = NOW(), error_message = %s WHERE id = %s",
                (f"Unsupported job: {job_type}/{subtype}", job_id),
            )
            failed += 1
        except Exception as exc:  # noqa: BLE001
            log.exception("Job %s failed", job_id)
            db.execute(
                "UPDATE jobs SET status = 'FAILED', completed_at = NOW(), error_message = %s WHERE id = %s",
                (str(exc)[:500], job_id),
            )
            failed += 1
    return {"completed": completed, "failed": failed}


def _write_export(job: dict[str, Any]) -> Path:
    table, columns, date_column = _CSV_SUBSCRIPTIONS[str(job["subtype"]).upper()]
    where = ["fiduciary_id = %s"]
    params: list[Any] = [str(job["fiduciary_id"])]
    if job.get("start_date"):
        where.append(f"{date_column} >= %s::date")
        params.append(job["start_date"])
    if job.get("end_date"):
        where.append(f"{date_column} <= %s::date + INTERVAL '1 day'")
        params.append(job["end_date"])
    rows = db.all(f"SELECT {columns} FROM {table} WHERE {' AND '.join(where)} ORDER BY {date_column} DESC", params)
    output_dir = settings.export_path
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"job_{job['id']}_{str(job['subtype']).lower()}.csv"
    fieldnames = [col.strip() for col in columns.split(",")]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(
                {key: (value.isoformat() if hasattr(value, "isoformat") else value) for key, value in row.items()}
            )
    log_event(
        "SYSTEM",
        str(job["fiduciary_id"]),
        "SYSTEM",
        str(job["id"]),
        "JOB_COMPLETED",
        {"output_file_path": str(path), "rows": len(rows)},
    )
    return path
