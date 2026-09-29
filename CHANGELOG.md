# Changelog

All notable changes in this branch are documented here for reviewers and operators upgrading from `origin/main`.

## [Unreleased] — P1/P2 Python port (branch `p1_changes`)

### Added

**P1 — purpose lifecycle, alerts, delivery**

- Admin `purpose` service: `set_purpose_state`, `close_purpose`, `list_purpose_lifecycle` (PL-01..04).
- Client `alerts` service: `notify_alert`, `acknowledge_alert`, `list_alerts` (NT-06..08).
- Policy: `duration_type` on every purpose; `notify_policy_change`, `request_reconsent`, auto-notify on `publish_policy` (CU-02, CU-03).
- Client `rights` service: nominations and data-correction requests (DPDP Section 15 / correction right).
- Background worker (`python_worker` in Compose): notification delivery, webhook dispatch, time-bound purpose closure, alert/grievance escalation, retention sweep, export jobs.
- SSRF guards on outbound webhooks and SMS/push gateways; HMAC webhook signatures.
- DB scripts: `13_breach_notification_deadline.sql`, `14_nomination_data_correction.sql`, `15_p1_consent_lifecycle_alerts.sql`.

**P2 — roles, MFA, retention, principal UX**

- Admin `retention` service: configurable retention policies (SA-08/10/12); worker reads these for DD-03.
- Admin `role` service: custom roles; seeded `AUDITOR` (SA-01..03).
- Operator MFA (TOTP, stdlib): `enrol_mfa`, `verify_mfa`; login MFA challenge; audit read gating (LG-06).
- Client `export_consent_history` (CSV, UD-04); grievance `reference_number` and `consent_record_id` (UD-10, GR-05, GR-14).
- DB script: `16_p2_roles_mfa_retention.sql`.

**Security & auth**

- `BOOTSTRAP_TOKEN` required for first-time Super-Admin setup (`/api/v1/bootstrap/setup`).
- Principal JWT sessions scoped to the token subject on client read/write paths (consent, grievances, notifications, rights, alerts, re-consent). Integrator API keys remain fiduciary-scoped.

**Tooling**

- Unit tests under `python_port/tests/` (31 tests: P1/P2 helpers, SSRF, TOTP, roles, retention).
- GitHub Actions: Ruff lint, compile/import smoke test, pytest, Docker build (see `.github/workflows/main.yml`).

### Changed

- `db/04_gaps.sql`: guarded encryption backfill when `app.enc_key` is not set (fresh init safety).
- Audit logging: discrete `purpose_id`, `consent_status`, `initiator`, `source_ip` columns where applicable (LG-02/03).
- Setup UI sends `bootstrap_token` with initial admin creation.

### Upgrade notes

- **New database volume:** Compose applies all `db/*.sql` on first Postgres start — no extra steps.
- **Existing database:** Run `db/13` through `db/16` manually against the live DB (scripts are idempotent). See [README — Database upgrades](README.md#database-upgrades).
- **Environment:** Add `BOOTSTRAP_TOKEN` (min 32 characters) before starting the app or worker.
- **Process:** Run the background worker in production (`python -m dpdpcms_py.worker` or Compose `python_worker`).

### Not in repository

- MeitY BRD traceability workbook and internal findings documents are local-only (listed in `.gitignore`).
