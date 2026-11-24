from __future__ import annotations

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.config import settings
from dpdpcms_py.modules.audit_logging.ledger import log_event
from dpdpcms_py.modules.notifications.api import _dpo_recipient, _notify


def escalate_overdue_grievances() -> dict[str, int]:
    """UD-12 / GR-09: auto-escalate grievances past their SLA due date."""
    # GR-09: escalate once the SLA due date plus the configured grace period
    # (GRIEVANCE_ESCALATION_HOURS) has passed. The UPDATE ... RETURNING is the
    # claim, so two workers can never escalate the same grievance twice (UD-12).
    rows = db.all(
        f"""
        UPDATE grievances SET status = 'ESCALATED', escalated_at = NOW(), last_updated_at = NOW()
        WHERE id IN (
            SELECT id FROM grievances
            WHERE status IN ('NEW', 'IN_PROGRESS') AND due_date IS NOT NULL
              AND due_date + make_interval(hours => %s) < NOW()
            ORDER BY due_date
            LIMIT %s
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id, {pii.dec_sql("user_id_enc")} AS user_id, fiduciary_id, reference_number, language
        """,
        (settings.grievance_escalation_hours, settings.worker_batch_size, *db.bind_key()),
    )
    count = 0
    for row in rows:
        gid = str(row["id"])
        fid = str(row["fiduciary_id"])
        # GR-03: answered in the language the grievance was filed in.
        _notify(
            "PRINCIPAL",
            str(row["user_id"]),
            fid,
            "GRIEVANCE_ESCALATED",
            {"reference_number": row.get("reference_number"), "language": row.get("language")},
        )
        # GR-07: an escalation must reach the fiduciary's DPO too, not only the
        # complainant — the DPO owns the SLA and can reassign or drive the
        # overdue grievance to resolution.
        _notify("DPO", _dpo_recipient(fid), fid, "GRIEVANCE_ESCALATED")
        log_event(str(row["user_id"]), fid, "APP", None, "GRIEVANCE_ESCALATED", {"grievance_id": gid})
        count += 1
    return {"escalated": count}
