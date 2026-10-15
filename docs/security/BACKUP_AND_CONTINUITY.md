# Backup, restore and continuity (Rule 6(1)(d))

## Backups

- `scripts/local/shell_scripts/manage.sh backup` writes a `pg_dump -Fc` to `backups/`.
- In production, schedule it at least daily. Copy each dump to encrypted storage in India, off the database host, and keep it for at least one year. That year is the Rule 6(1)(e) floor.
- Dumps contain ciphertext and pseudonyms. The keys never go into the backup location (see [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md)).

## Restore test

`scripts/local/shell_scripts/restore-test.sh [dump]` runs these steps:

1. Restores the newest dump, or the one named, into a scratch database.
2. Counts the core tables.
3. Checks that every audit-ledger row still links to its predecessor.
4. Recomputes every ledger row's hash with the application's own verifier (`verify_chain`, run in the `python_app` container against the scratch database), so a row edited in place that kept its links is caught too.
5. Drops the scratch database.

It never touches the live database. Run it monthly and after every migration, and record the result below.

Targets:

- **RPO** (data loss tolerated): 24 hours, set by the backup frequency.
- **RTO** (time to restore): 4 hours.

Change both only by a DPO decision.

## Worker continuity

The worker runs retention sweeps, purpose closure, grievance and alert escalation, notification and webhook delivery, breach-deadline alerts, and the chain verification. All of these stop silently if the worker is down. Nothing inside the API starts the worker.

- Each cycle writes `worker_heartbeat`.
- `GET /healthz/worker` returns 503 in two cases:
  - **stale**: no completed cycle in 5 poll intervals, with a 10-minute minimum;
  - **degraded**: a sweep failed in the last cycle.
- Point the uptime monitor at `/healthz/worker` as well as `/healthz`, and page the infrastructure lead on a 503.
- Both endpoints are unauthenticated, so they return `{"status": ...}` only. A monitor that sends `X-Health-Token: <HEALTHZ_TOKEN>` also gets `last_cycle_at`, `age_seconds` and `failed_sweeps`. Database errors go to the application log, never to the caller.

## Restore-test log

| Date | Dump | Result | Restore time | By |
| --- | --- | --- | --- | --- |
| | | | | |
