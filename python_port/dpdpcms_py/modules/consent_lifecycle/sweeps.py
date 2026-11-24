from __future__ import annotations

import logging

from dpdpcms_py.kernel import db
from dpdpcms_py.kernel.config import settings
from dpdpcms_py.modules.audit_logging.ledger import log_event
from dpdpcms_py.modules.consent_lifecycle.purpose_lifecycle import close_purpose_exec
from dpdpcms_py.modules.notifications.api import _dpo_recipient, _notify

log = logging.getLogger("dpdpcms.jobs")


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
    errors = 0
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
            # P11-08: a failed closure is an error the operator sees in the
            # cycle summary, never an innocent-looking "closed: 0".
            errors += 1
            log.exception("Time-bound closure failed for %s/%s", fid, purpose_id)
    out = {"closed": closed, "scanned": len(due)}
    if errors:
        out["errors"] = errors
        out["error"] = f"{errors} time-bound closure(s) failed; see the worker log."
    return out


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
        _notify("DPO", _dpo_recipient(fid), fid, "PURGE_OVERDUE")
        log_event(
            "SYSTEM",
            fid,
            "SYSTEM",
            None,
            "PURGE_OVERDUE",
            {"purge_request_id": str(row["id"]), "purpose_id": row["purpose_id"]},
        )
    return {"flagged": len(rows)}
