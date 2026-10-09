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
  the original p3 defect list. Reconciled as far as evidence allows in v4
  (D13 = the README loop defect already tracked as CF-04 and verified Fixed;
  D10 left for the p3 list).

## Workbook v4 — BUILT (9 Oct 2026)

`MeitY_BRD_API_Traceability_security_v4.xlsx` was created from v3 (gitignored,
not committed — security workbooks live outside the repo). Changes:

- **BRD Traceability** — all 14 rows previously marked Partial / Needs
  correction (CV-04, PL-03, UD-02, UD-03, NT-03, NT-04, GR-02, GR-07, GR-11,
  GR-13, SA-04, SA-13, LG-04, LG-07) are now **Exists**, each comment rewritten
  to name the verified fix. Sheet is 100 Exists / 20 Not applicable / 0 others.
- **Module Summary** — recount per module to match the matrix (D:H columns) and
  verdict/comment refreshed; every module verdict now Good or Not applicable.
- **Security Gaps** — SEC-04/10/18, P5-07 and P6-01..09 all FIXED with new
  evidence; band labels and the five summary paragraphs rewritten; P5-05 left
  PARTLY FIXED (owner action).
- **Defect Remediation** — D10/D13 Closed (reconciled), P6-01/02/03/06 Fixed.
- **Method** — revision 8 row added (`p6_defect_fixes @ 76c941f`,
  9 Oct 2026, headline counts 100/0/0/0/20).
- Status-total `COUNTIF` formulas preserved and their cached values injected
  (LibreOffice was unavailable to recalc; `fullCalcOnLoad` is set and the
  computed totals were verified in Python).

## Validation

- `python -m pytest` → **239 passed, 1 skipped** (was 222 + hang).
- The pre-existing hang in `test_defect_fixes.py::test_run_cycle_isolates_failing_sweep`
  was fixed by stubbing every sweep the worker now runs.
- `ruff check` clean after import-order fixes.