from __future__ import annotations

import argparse
import logging
import time
from collections.abc import Callable
from typing import Any

from dpdpcms_py.registry import SWEEPS

log = logging.getLogger("dpdpcms.worker")


def run_cycle(dry_run: bool = False) -> dict[str, Any]:
    """One pass over every background sweep. Called by the scheduler loop.

    Returns per-sweep counts so the operator can confirm each requirement the
    worker serves (PL-04, NT-09, UD-12, GR-09, SA-09/SA-11, LG-07) is running.
    """
    if dry_run:
        return {"dry_run": True, "sweeps": list_sweeps()}
    # Every module declares its own sweeps in its manifest; dpdpcms_py.registry
    # puts them in the order the heartbeat has always reported.
    sweeps: dict[str, Callable[[], Any]] = {name: sweep.func for name, sweep in SWEEPS.items()}
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
    from dpdpcms_py.kernel import db
    from dpdpcms_py.kernel.config import settings

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
    lines = []
    for sweep in SWEEPS.values():
        owner = sweep.func.__module__.removeprefix("dpdpcms_py.").removeprefix("modules.").removeprefix("extensions.")
        lines.append(f"{owner}.{sweep.func.__name__}  ({sweep.note})")
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description="TSI DPDP CMS background worker")
    parser.add_argument("--once", action="store_true", help="Run a single sweep cycle and exit.")
    parser.add_argument("--poll", type=int, default=None, help="Override WORKER_POLL_SECONDS.")
    args = parser.parse_args()

    from dpdpcms_py.kernel.config import settings

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
