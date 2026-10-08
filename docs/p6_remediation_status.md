# p6_defect_fixes — remediation status (workbook v3 findings)

Progress snapshot. All code fixes below are implemented, tested, and committed on
branch `p6_defect_fixes`. The security workbook v3 file itself was NOT updated
by design — the worksheets still show the pre-fix statuses.

## What was fixed (code + tests)

| Finding | Fix |
|---|---|
| P6-01 / LG-04 | `audit.verify_chain` now walks the unfiltered global chain and filters only the report. Scoped verification on an intact ledger returns intact (fixes the false LINK_MISMATCH that blocked every non-ADMIN certificate). |
| P6-02 / UD-02 | `get_consent_record_details` policy_id branch requires + binds `user_id`; key callers must name a principal. Schema updated. Response now carries per-purpose lifecycle state + retention (DD-01 dashboard substitute). |
| P6-03 / LG-07 | `download_file` returns base64 bytes in the authenticated JSON response; admin dashboard + DPO reports pages fetch with Authorization header and hand the browser a blob. No `?auth=` in any URL. |
| P6-04 | `throttle.record_failure` increments atomically server-side (`INSERT ... ON CONFLICT ... RETURNING`); `main.client_ip` walks X-Forwarded-For right-to-left and supports CIDR in `TRUSTED_PROXY_IPS`. |
| P6-05 | `_is_read_classified` folds in `CLIENT_FUNC_SCOPES` READ, so `validate_consent` / `sync` work over GET. |
| P6-06 / SA-13 | `erase_cms_copy`: consent-record metadata scrub + notification_deliveries join moved ahead of the generic re-key loop. |
| P6-07 | `create_nomination` binds `COALESCE(%s, NOW())` for `valid_from`. |
| P6-08 | `parent-consent.html` looks checkboxes up via a JS map, not an escaped-id string. |
| P6-09 | `db/21` OTP cleanup restricted to terminal webhook_deliveries statuses. |
| SEC-04 | Key-initiated `erasure_request` requires a real consent record for the principal (closes WRITE+PURGE escalation to `erase_cms_copy`). |
| SEC-10 | `verify_certificate`: constant-time compare, re-derives trail against audit_logs, refuses certs on broken chains; console Verify button on legal page. |
| SEC-18 | `update_user` only sets fiduciary_id when explicitly supplied + refuses NULL; new `db/22_sec18_null_fiduciary_block.sql` deactivates legacy NULL-fiduciary non-ADMIN operators. |
| PL-03 | CMS reads `purge_requests.action`: ERASE deletes the profile, DE_IDENTIFY re-keys it. |
| GR-07 | Overdue-grievance sweep notifies the DPO as well as the principal. |
| P5-07 | `prune_old_webhook_deliveries` enforces the Rule 6(1)(e) 365-day floor (`RULE_6_1_E_MIN_RETENTION_DAYS`); stated never-prune policy for audit/notification tables. |

## Still open (deliberately not code)

- **P5-05** — the findings workbook blob is still public on the published
  `p5_changes` branch. Needs an owner with push access to delete/rewrite that
  branch. `*.xlsx` IS gitignored in-repo.
- **D10/D13** — bookkeeping only: reconciling the two p3 defect letters needs
  the original p3 defect list.
- **Workbook v4** — NOT built (per instruction). When it is wanted, copy v3,
  update Security Gaps / Defect Remediation / BRD Traceability statuses and the
  Module Summary counts, add a Method revision row.

## Validation

- `python -m pytest` → **239 passed, 1 skipped** (was 222 + hang).
- The pre-existing hang in `test_defect_fixes.py::test_run_cycle_isolates_failing_sweep`
  was fixed by stubbing every sweep the worker now runs.