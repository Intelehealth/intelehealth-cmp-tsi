from __future__ import annotations

import argparse
import logging
import time
from typing import Any

from . import delivery, jobs, webhooks

log = logging.getLogger("dpdpcms.worker")


def run_cycle(dry_run: bool = False) -> dict[str, Any]:
    """One pass over every background sweep. Called by the scheduler loop.

    Returns per-sweep counts so the operator can confirm each requirement the
    worker serves (PL-04, NT-09, UD-12, GR-09, SA-09/SA-11, LG-07) is running.
    """
    if dry_run:
        return {"dry_run": True, "sweeps": list_sweeps()}
    summary: dict[str, Any] = {
        "delivery": delivery.process_pending_notifications(),
        "webhooks": webhooks.process_pending_webhooks(),
        "time_bound_purposes": jobs.close_due_time_bound_purposes(),
        "alerts": jobs.escalate_stale_alerts(),
        "grievances": jobs.escalate_overdue_grievances(),
        "retention": jobs.run_retention_sweep(),
        "jobs": jobs.execute_queued_jobs(),
    }
    return summary


def list_sweeps() -> list[str]:
    return [
        "delivery.process_pending_notifications   (NT-04 delivery adapter)",
        "webhooks.process_pending_webhooks        (CC-09/CU-08/CW-08 dispatcher)",
        "jobs.close_due_time_bound_purposes       (PL-01 time-bound closure)",
        "jobs.escalate_stale_alerts               (NT-09)",
        "jobs.escalate_overdue_grievances         (UD-12, GR-09)",
        "jobs.run_retention_sweep                 (PL-04/SA-09, SA-11)",
        "jobs.execute_queued_jobs                 (LG-07 export jobs)",
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
