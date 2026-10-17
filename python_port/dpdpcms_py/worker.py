from __future__ import annotations

import argparse
import logging
import time
from collections.abc import Callable
from typing import Any

from . import audit, delivery, jobs, throttle, webhooks
from .services.catalog import retire_all_superseded_versions

log = logging.getLogger("dpdpcms.worker")


def run_cycle(dry_run: bool = False) -> dict[str, Any]:
    """One pass over every background sweep. Called by the scheduler loop.

    Returns per-sweep counts so the operator can confirm each requirement the
    worker serves (PL-04, NT-09, UD-12, GR-09, SA-09/SA-11, LG-07) is running.
    """
    if dry_run:
        return {"dry_run": True, "sweeps": list_sweeps()}
    sweeps: dict[str, Callable[[], Any]] = {
        "delivery": delivery.process_pending_notifications,
        "webhooks": webhooks.process_pending_webhooks,
        "time_bound_purposes": jobs.close_due_time_bound_purposes,
        "superseded_policies": retire_all_superseded_versions,
        "alerts": jobs.escalate_stale_alerts,
        "grievances": jobs.escalate_overdue_grievances,
        "retention": jobs.run_retention_sweep,
        "jobs": jobs.execute_queued_jobs,
        "overdue_purges": jobs.flag_overdue_purges,
        "legal_holds": jobs.release_expired_legal_holds,
        "revoked_tokens": jobs.prune_revoked_tokens,
        "expired_api_keys": jobs.expire_lapsed_api_keys,
        "throttles": throttle.prune_expired,
        "sso_nonces": jobs.prune_sso_nonces,
        "nominations": jobs.expire_nominations,
        "webhook_deliveries": jobs.prune_old_webhook_deliveries,
        "notification_deliveries": jobs.prune_old_notification_deliveries,
        "audit_chain": audit.record_chain_verification,
        "audit_partitions": jobs.archive_audit_partitions,
        "security_monitor": jobs.flag_security_anomalies,
        "breach_deadlines": jobs.flag_breach_board_deadlines,
    }
    # Each sweep is isolated: one failing sweep is logged and reported, and the
    # rest of the cycle still runs.
    summary: dict[str, Any] = {}
    for name, sweep in sweeps.items():
        try:
            summary[name] = sweep()
        except Exception as exc:  # noqa: BLE001 - one bad sweep must not halt the others
            log.exception("Sweep %s failed", name)
            summary[name] = {"error": f"{type(exc).__name__}: {exc}"}
    record_heartbeat(summary)
    return summary


def record_heartbeat(summary: dict[str, Any]) -> None:
    """R6-d: a stopped worker silently stops retention, escalation and delivery;
    each cycle leaves a heartbeat that /healthz/worker reports on."""
    from . import db
    from .config import settings

    failed = sorted(name for name, out in summary.items() if isinstance(out, dict) and out.get("error"))
    try:
        db.execute(
            """
            INSERT INTO worker_heartbeat (worker_name, last_cycle_at, poll_seconds, failed_sweeps)
            VALUES ('default', NOW(), %s, %s)
            ON CONFLICT (worker_name) DO UPDATE SET
                last_cycle_at = EXCLUDED.last_cycle_at, poll_seconds = EXCLUDED.poll_seconds,
                failed_sweeps = EXCLUDED.failed_sweeps
            """,
            (settings.worker_poll_seconds, db.as_jsonb(failed)),
        )
    except Exception:  # noqa: BLE001 - a heartbeat failure must not stop the cycle
        log.exception("Could not record the worker heartbeat")


def list_sweeps() -> list[str]:
    return [
        "delivery.process_pending_notifications   (NT-04 delivery adapter)",
        "webhooks.process_pending_webhooks        (CC-09/CU-08/CW-08 dispatcher)",
        "jobs.close_due_time_bound_purposes       (PL-01 time-bound closure)",
        "catalog.retire_all_superseded_versions   (CU-05 superseded notice versions)",
        "jobs.escalate_stale_alerts               (NT-09)",
        "jobs.escalate_overdue_grievances         (UD-12, GR-09)",
        "jobs.run_retention_sweep                 (PL-04/SA-09, SA-11)",
        "jobs.execute_queued_jobs                 (LG-07 export jobs)",
        "jobs.flag_overdue_purges                 (SA-09 unconfirmed purges)",
        "jobs.release_expired_legal_holds         (CW-11 legal hold end)",
        "jobs.prune_revoked_tokens                (SA-05 revocation list)",
        "jobs.expire_lapsed_api_keys              (SEC-07 expiry enforcement)",
        "throttle.prune_expired                   (SEC-01/03 throttle table)",
        "jobs.prune_sso_nonces                    (SEC-14 one-time SSO nonces)",
        "jobs.expire_nominations                  (P6-07 nomination window expiry)",
        "jobs.prune_old_webhook_deliveries          (SEC-13/P5-07 webhook retention)",
        "jobs.prune_old_notification_deliveries   (SA-13 notification delivery retention)",
        "audit.record_chain_verification         (P6-12 daily full-ledger verification)",
        "jobs.archive_audit_partitions           (yearly audit partitions; archive beyond AUDIT_LIVE_YEARS)",
        "jobs.flag_security_anomalies            (Rule 6(1)(c) failed sign-in bursts)",
        "jobs.flag_breach_board_deadlines        (s.8(6) 72-hour Board intimation clock)",
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="TSI DPDP CMS background worker")
    parser.add_argument("--once", action="store_true", help="Run a single sweep cycle and exit.")
    parser.add_argument("--poll", type=int, default=None, help="Override WORKER_POLL_SECONDS.")
    args = parser.parse_args()

    from .config import settings

    poll = args.poll or settings.worker_poll_seconds
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log.info("TSI DPDP CMS worker starting (poll=%ss)", poll)

    if args.once:
        summary = run_cycle()
        log.info("Cycle complete: %s", summary)
        return

    if poll <= 0:
        poll = 30
    while True:
        started = time.monotonic()
        try:
            summary = run_cycle()
            log.info("Cycle %s", summary)
        except Exception:  # noqa: BLE001 - the loop must survive a bad sweep
            log.exception("Worker cycle failed")
        elapsed = time.monotonic() - started
        time.sleep(max(1, poll - elapsed))


if __name__ == "__main__":
    main()
