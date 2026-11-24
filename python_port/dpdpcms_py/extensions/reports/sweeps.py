from __future__ import annotations

import csv
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.config import settings
from dpdpcms_py.kernel.service import csv_safe
from dpdpcms_py.modules.audit_logging.ledger import log_event
from dpdpcms_py.modules.consent_lifecycle.api import close_due_time_bound_purposes

log = logging.getLogger("dpdpcms.jobs")


_CSV_SUBSCRIPTIONS: dict[str, tuple[str, str, str]] = {
    # subtype -> (table, default_columns, date_column)
    "CONSENT": ("consent_records", "id,user_id,policy_id,policy_version,consent_status_general,timestamp", "timestamp"),
    "PRINCIPAL": (
        "data_principal",
        "user_id,fiduciary_id,last_consent_mechanism,age_category,created_at",
        "created_at",
    ),
    "GRIEVANCE": ("grievances", "id,user_id,type,subject,status,submission_timestamp", "submission_timestamp"),
    # P9-08 / LG-07: every hashed column plus both hashes and the hash version,
    # so whoever receives the export can re-verify the chain it came from.
    "AUDIT": (
        "audit_logs",
        "id,fiduciary_id,timestamp,user_id,service_type,service_id,audit_action,context_details,"
        "purpose_id,consent_status,initiator,source_ip,prev_log_hash,current_log_hash,system_metadata",
        "timestamp",
    ),
}


# Export columns holding a principal id: stored as <col>_enc/<col>_hmac (db/34),
# decrypted for the export and written masked - every export job is operator
# requested. audit_logs.user_id is already a pseudonym and is not listed.
_CSV_PRINCIPAL_COLUMNS = {"CONSENT": {"user_id"}, "PRINCIPAL": {"user_id"}, "GRIEVANCE": {"user_id"}}


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
    subtype = str(job["subtype"]).upper()
    table, columns, date_column = _CSV_SUBSCRIPTIONS[subtype]
    principal_columns = _CSV_PRINCIPAL_COLUMNS.get(subtype, set())
    fieldnames = [col.strip() for col in columns.split(",")]
    select = ", ".join(
        f"{pii.dec_sql(f'{col}_enc')} AS {col}" if col in principal_columns else col for col in fieldnames
    )
    where = ["fiduciary_id = %s"]
    params: list[Any] = [*(db.bind_key() * len(principal_columns)), str(job["fiduciary_id"])]
    if job.get("start_date"):
        where.append(f"{date_column} >= %s::date")
        params.append(job["start_date"])
    if job.get("end_date"):
        # Exclusive upper bound: the whole end_date, and exactly the window the
        # AUDIT chain verdict below examines (P10-06).
        where.append(f"{date_column} < %s::date + INTERVAL '1 day'")
        params.append(job["end_date"])
    if subtype == "AUDIT":
        # The whole ledger, archived years included: the chain verdict below
        # covers them, so the file must too.
        from dpdpcms_py.modules.audit_logging.ledger import ledger_source

        table = ledger_source()
    rows = db.all(f"SELECT {select} FROM {table} WHERE {' AND '.join(where)} ORDER BY {date_column} DESC", params)
    for row in rows:
        for col in principal_columns:
            row[col] = pii.mask(row[col])
    output_dir = settings.export_path
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"job_{job['id']}_{str(job['subtype']).lower()}.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        # PT-02: neutralise formula cells - except in the AUDIT export, whose
        # cells must stay byte-exact so every row hash recomputes from the file
        # (P9-08). Open that file as text data, never as a live spreadsheet.
        audit = str(job["subtype"]).upper() == "AUDIT"
        for row in rows:
            writer.writerow(
                {key: _csv_value(value) if audit else csv_safe(_csv_value(value)) for key, value in row.items()}
            )
    context: dict[str, Any] = {"output_file_path": str(path), "rows": len(rows)}
    if str(job["subtype"]).upper() == "AUDIT":
        # P9-08: ship the chain verdict for the exported range with the file.
        # P10-06: the verdict covers exactly the exported window - bounded by
        # end_date as well as start_date - and attests an intact chain ONLY
        # when every row of that window was examined. A truncated walk that
        # found nothing broken proves nothing, so it never reads as intact.
        from dpdpcms_py.modules.audit_logging.ledger import verify_chain

        since = _day_start(job.get("start_date"))
        until = _day_start(job.get("end_date"), plus_days=1)
        verdict = verify_chain(fiduciary_id=str(job["fiduciary_id"]), since=since, until=until)
        attested = bool(verdict.get("intact")) and bool(verdict.get("coverage_complete"))
        verdict = {
            **verdict,
            "chain_intact": attested,
            "attestation": "INTACT"
            if attested
            else ("BROKEN" if verdict.get("broken_count") or verdict.get("foreign_broken_count") else "NOT_ATTESTED"),
            "export_window": {"start_date": job.get("start_date"), "end_date": job.get("end_date")},
        }
        verdict_path = path.with_suffix(".verification.json")
        verdict_path.write_text(json.dumps(db.to_jsonable(verdict), indent=2, default=str), encoding="utf-8")
        context["chain_intact"] = attested
        context["chain_coverage_complete"] = bool(verdict.get("coverage_complete"))
        context["chain_verification_path"] = str(verdict_path)
    log_event(
        "SYSTEM",
        str(job["fiduciary_id"]),
        "SYSTEM",
        str(job["id"]),
        "JOB_COMPLETED",
        context,
    )
    return path


def _day_start(value: Any, plus_days: int = 0) -> datetime | None:
    """Midnight UTC of a job's start_date / end_date (a date or ISO string)."""
    if not value:
        return None
    day = value if hasattr(value, "year") else datetime.fromisoformat(str(value)[:10])
    start = datetime(day.year, day.month, day.day, tzinfo=UTC)
    return start + timedelta(days=plus_days)


def _csv_value(value: Any) -> Any:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return value
