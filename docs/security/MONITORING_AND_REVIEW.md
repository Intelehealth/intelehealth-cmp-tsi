# Monitoring and review of access (Rule 6(1)(c))

A log satisfies only the first part of Rule 6(1)(c). The clause also asks for monitoring and for review.

## What the system watches

| Signal | Detector | Raises |
| --- | --- | --- |
| Ledger tampering | `audit.record_chain_verification`: the worker walks the full chain once a day | A stored verdict in `audit_chain_verifications`; a BROKEN verdict appears on the console audit page |
| 20 or more failed sign-ins in 60 minutes for one fiduciary | `jobs.flag_security_anomalies` | A `SECURITY_AUTH_FAILURE_BURST` alert and a DPO notice, once per window |
| Board intimation due or missed | `jobs.flag_breach_board_deadlines` | `BREACH_BOARD_DEADLINE_DUE` / `_MISSED` alerts and DPO notices |
| Worker stopped, or a sweep failing | `/healthz/worker` | HTTP 503 for the uptime monitor (detail only with `X-Health-Token`) |
| Someone reading the ledger | `AUDIT_LOG_READ` events on every audit read, and in the access report | Reviewed monthly (below) |
| Alerts nobody acknowledged | `jobs.escalate_stale_alerts` | Escalation after `ALERT_ESCALATION_HOURS` |

## Shipping logs to a SIEM

Export `audit_logs` to the organisation's SIEM or log store, together with the application and worker stdout and the reverse-proxy access logs. The incremental cursor is `(timestamp, id)`. Alert there on at least:

- a burst of 403 responses from one API key or operator, across tenants;
- `LOGIN_FAILURE` from a new country or ASN;
- any `ROLE_*` or `OPERATOR_*` change outside business hours;
- an audit export or evidence certificate of an unusual size.

## Review cadence

The DPO, or a named delegate, reviews the following and signs below:

- **Monthly**: alerts raised and how each was handled; operator and API-key changes; failed sign-in trends, operator and principal; who read the audit ledger (`AUDIT_LOG_READ`); the latest chain verdict.
- **Quarterly**: an access review of every operator account and role, every API key and its DPA, and every database role. That includes members of `tsi_tenant_reader` and their rows in `tsi_reader_tenants`.

## Review log

| Period | Reviewer | Findings | Actions |
| --- | --- | --- | --- |
| | | | |
