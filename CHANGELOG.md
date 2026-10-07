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

- Unit tests under `python_port/tests/` (173 tests: P1/P2 helpers, SSRF, TOTP, roles, retention, a regression test per open defect in `test_defect_fixes.py`, BRD traceability rules in `test_brd_traceability.py`, the workbook v4 defects in `test_review_v4_fixes.py`, the workbook v5 defects in `test_review_v5_fixes.py`, and the bugs found re-verifying the BRD sheet in `test_brd_v5_bugs.py`).
- GitHub Actions: Ruff lint, compile/import smoke test, pytest, Docker build (see `.github/workflows/main.yml`).
- Local deployment scripts in `scripts/local/` (preflight, init-env, deploy, migrate, bootstrap-admin, smoke-test, manage), in PowerShell (`.ps1`) and bash (`.sh`, for Linux, macOS, Git Bash and WSL), and the plan in `docs/LOCAL_DEPLOYMENT.md`.
- `docker-compose.yml`: the exports volume and `TSI_EXPORT_PATH` are fixed at `/var/lib/tsi/exports/` inside the containers. A relative `TSI_EXPORT_PATH` in `.env` (meant for native runs) used to break `docker compose up`. The app and worker now also load `.env` via `env_file`, so optional settings (DigiLocker, SSO, attachment limit, DUMMY_OTP opt-in) reach the containers.

### Changed

- `db/04_gaps.sql`: guarded encryption backfill when `app.enc_key` is not set (fresh init safety).
- Audit logging: discrete `purpose_id`, `consent_status`, `initiator`, `source_ip` columns where applicable (LG-02/03).
- Setup UI sends `bootstrap_token` with initial admin creation.

### Fixed (Open Defects sheet, traceability workbook v3)

- **#1** `principal_login` now verifies a server-side OTP: `request_principal_otp` stores only an HMAC of a random 6-digit code (5-minute expiry, single use, 5 attempts, 5 requests per 15 minutes), delivers it through the fiduciary's `OTP` webhook, and never returns it. `DUMMY_OTP` mode (fixed code `1234`) works only where `ALLOW_DUMMY_OTP` permits — by default only `TSI_DPDP_CMS_ENV=local`. `list_active_fiduciaries` now returns `otp_mode` so the rights portal shows "Send OTP".
- **#2** Admin routes reject principal JWTs (`typ: principal`) and any token that does not map to an ACTIVE operator; the role is taken from the database, not the token claim.
- **#3** `enrol_mfa` refuses to replace the secret on an MFA-enabled account (403 from a password-only session, 409 from a verified one).
- **#4** `delivery._recipient_email` decrypts `email_enc` (it decrypted the key) and never raises.
- **#5** `worker.run_cycle` isolates each sweep; a failure is logged and reported as `{"error": ...}` while the rest run.
- **#6** Every admin-category function is gated by the roles table (`<resource>:read|write|manage`, write implies read). Roles carry `fiduciary_id` (custom roles are per tenant); a tenant can only grant permissions it holds. Fiduciary-scoped operators are bound to their own tenant like API keys.
- **#7** Outbound webhook/gateway POSTs connect to the IP that passed SSRF validation (no second DNS lookup) and never follow redirects.
- **#8** TOTP codes are single-use (last accepted step counter stored per operator); `verify_mfa` locks for 15 minutes after 5 bad codes and only ever checks the caller's own secret.
- **#9** `update_purge_status` validates the status enum (code, JSON schema, `CHECK` constraint); by-id reads and writes across services are tenant-scoped, including `generate_recovery_key` (own tenant, non-ADMIN only), `assign_purge_request` and `assign_grievance` (assignee must be in the same tenant).
- **#10** CI runs `pytest` unconditionally (an empty or missing suite fails) and now triggers on `main`.
- DB script: `17_defect_fixes.sql`. `16_p2_roles_mfa_retention.sql` stays re-runnable after it.

### Fixed (Defect Remediation sheet, traceability workbook v4)

- **#7 / D12** The SSRF allow-list judges IPv6 addresses that reach IPv4 (`::ffff:169.254.169.254`, `::127.0.0.1`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4, Teredo) by the IPv4 address they embed, and refuses `::`, the IPv4-mapped range, documentation ranges and anything `ipaddress` reports as reserved, loopback, link-local or multicast. Zone ids (`fe80::1%eth0`) are stripped before the check.
- **D11** The role gate no longer treats `validate_*` as a read: `validate_fiduciary_domain` needs `fiduciary:write` and `validate_consent` (logs the check, can notify the principal) needs `consent:write`. The two side-effect-free `validate_completeness` functions are mapped to `ropa:read` / `retention:read`. A test fails if any read-classified service function contains SQL that writes.
- **D13** The README upgrade loop had a literal `
` that broke the shell continuation before `17` and `18`; the production checklist said `13`–`16`. Both now cover `13`–`18`.
- **D14** Wallet calls are authorised as the function their `action` runs: `GRANT_CONSENT` is checked as `record_consent`, `GLOBAL_ERASURE` / `REVOKE_PURPOSE` as `erasure_request`, so a READ-scoped key can no longer write through `sync`. Unknown actions return 400 instead of a silent success.
- **D15** New `get_grievance_attachment` (client READ scope, admin `grievance:read`) returns an attachment's metadata and base64 content, scoped to the tenant and, for principal tokens, to the complainant. A confirmed whole-account erasure deletes the principal's attachment rows and files (files still referenced by another grievance are kept, since storage is content-addressed).
- **UD-04** The consent-history PDF now renders every Eighth Schedule language. `pdfgen.py` uses fpdf2 with HarfBuzz text shaping (`uharfbuzz`) and bundled Noto fonts (OFL, `python_port/dpdpcms_py/fonts/`, ~2.3 MB), so Indic conjuncts and vowel signs compose correctly and Urdu/Kashmiri/Sindhi run right-to-left; only the fonts a document uses are embedded. Purposes are listed by name from the policy block in the record's `language_selected` (or `language`), falling back to English. The old writer replaced anything outside Latin-1 with `?`. New dependencies: `fpdf2`, `uharfbuzz`, `fonttools`.
- **#10** Already fixed on this branch (suite present, CI fails rather than skips); the workbook v4 finding was made against `p3_changes`.

### Fixed (Defect Remediation sheet, traceability workbook v5)

- **P4-01** Wallet actions work again. The D14 rewrite of `_func` stays before authentication (so scopes are checked against the real function), but schema validation now runs after `authenticate()`, once the token has bound `fiduciary_id` and, for a principal token, `user_id`. The payload is validated against the resolved function's schema. The wallet client's `command` field is accepted as an alias for `action`.
- **P4-02** `_func` is trimmed and lower-cased once at the dispatch entry point, and the validator now fails closed: a function with no schema, or a name that is not a plain identifier, is rejected with 400. The seven API functions that had no schema now have one (`download_file`, `get_api_key_details`, `update_api_key_status`, `list_access_report`, `list_active_policies`, `logout`, `sync`). A test fails if any service function lacks a schema.
- **P4-03** CI runs on pushes to `main`, `p*_changes` and `brd-*` branches, on every pull request to `main`, and on manual dispatch.
- **CF-01** The static route returns 404 for any path with a `WEB-INF` or `META-INF` segment, matched case-insensitively and ignoring trailing dots, so the validator schemas are no longer public.
- **CF-02** Every console page that renders server or user text (DPO grievances, ROPA, compliance, breach, audit, policies, team, settings, legal, dashboard, consents, principals; admin API keys, apps, fiduciaries, users) passes it through `esc()`. Inline `onclick="fn('${id}')"` handlers that embedded data are replaced with `data-*` attributes and `addEventListener`.
- **D15** The DPO grievance detail view lists a grievance's attachments with a Download button (`get_grievance_attachment`) and has an upload control (`upload_grievance_attachment`, PDF/PNG/JPEG/text, type checked in the browser and again on the server).
- **D11** Added regression tests for the default-deny branch: an unrecognised verb resolves to `:write`, and `READ_PREFIXES` is pinned to the closed set.
- **CF-03 / CF-04** Already fixed on this branch (test suite present; README upgrade loop lists `13`–`18`). The workbook v5 findings were made against `p4_changes`.
- **CF-05** Cookie consent (BRD 4.2) is out of scope for this release.

### Fixed (BRD Traceability sheet, workbook v5 re-verification)

- **PL-02** Closing a purpose that a policy still declares no longer blocks all consent under that policy. A closed purpose may be declined or left out; only granting it is refused (403). `check_consent_alignment` returns the closed set and `check_explicit_choices` exempts it.
- **SA-12** The 7-year retention floor is judged in the policy's own unit (`meets_statutory_floor`): 7 YEARS, 84 MONTHS or 2555 DAYS pass. The old 2557-day constant rejected a 7-year policy (7 x 365 = 2555).
- **LG-04** Audit hash v2 covers every stored column exactly as stored (including the pseudonymised `user_id`, `fiduciary_id`, `purpose_id`, `consent_status`, `initiator`, `source_ip`), with naive-UTC, strictly increasing timestamps. New admin `audit/verify_audit_chain` (global ADMIN, `audit:read`) recomputes the chain and reports link or content breaks; pre-v2 rows are checked for linkage only. New `db/19_audit_ledger_integrity.sql` makes `audit_logs` append-only (UPDATE, DELETE and TRUNCATE raise).
- **CC-09 / CU-08** A send-time SSRF or DNS refusal is a failed attempt for that webhook config instead of an exception that aborted the sweep and stranded the delivery in PROCESSING.
- **NT-05** `mark_notification_read` accepts `id` (the schema and documented sample) or `notification_id`; the schema requires one of them.
- **CW-03 / UD-05** A principal holds one active consent per policy, not per fiduciary: `record_consent` retires only the same policy's record. `validate_consent` and `get_withdrawal_implications` look across every active record, and withdrawal/erasure applies to each active record holding a named purpose (optionally narrowed by `policy_id`; response adds `consent_record_ids`).

### Fixed (BRD Traceability sheet, workbook v3)

- **Consent capture (CC-02..07):** policies accept all 22 Eighth Schedule languages (`brx`, `doi`, `kok`, `mai`, `mni`, `sat` added) and the DPO console names them. `record_consent` needs an explicit `consent_granted` boolean for every declared purpose (no omissions, duplicates or implied consent). `consent_mechanism`, `ip_address` and `user_agent` are server-observed; the caller's claims go to `client_metadata`; `session_id` is the principal session's token id (`session_source` CMS) or the integrator's claim (CLIENT). Withdrawal appends a new record (`supersedes_record_id`) instead of overwriting.
- **Guardian verification (CC-05):** `record_parent_consent` verifies `EXISTING_ACCOUNT` (guardian is an adult principal of the fiduciary) and `DIGILOCKER` (through `DIGILOCKER_VERIFY_URL`); other mechanisms are recorded as assertions. A minor's consent needs a `VERIFIED` log; a bare `guardian_id` no longer suffices.
- **Validation (CV-04):** `validate_consent` returns the record id, timestamp, status, policy and per-purpose state.
- **Withdrawal (CW-04, CW-11):** new `get_withdrawal_implications` (per-purpose consequence, mandatory flag, legal retention). Erasure requests check retention policies with a `legal_reference` when filed: held requests are `LEGAL_HOLD_APPLIED` with `hold_until`, cannot be confirmed complete early, and are released by the worker.
- **Purpose lifecycle (PL-03):** closure defers to the governing retention period (same lookup as the sweep) instead of purging at once; purge requests carry `action` (ERASE / DE_IDENTIFY), taken from the retention policy or the closure.
- **Dashboard (UD-03, UD-04):** `list_consent_history` filters by purpose, status and date; `export_consent_history` accepts `format=pdf` (built-in PDF writer). The wallet `sync_token` is only returned to the principal's own session.
- **Notifications (NT-07):** consent given, updated, withdrawn and erasure requested raise acknowledgeable alerts.
- **Grievances (GR-02..13):** type and status enums; resolving needs a summary; `get_grievance` by `reference_number`; notifications at assignment, in progress, escalation and resolution; `add_grievance_communication` appends to the action log; new `submit_grievance_feedback` and `upload_grievance_attachment` (type allow-list, size limit, stored by SHA-256). Escalation honours `GRIEVANCE_ESCALATION_HOURS` and claims rows so two workers can't double-escalate.
- **Administration (SA-05..13):** logout revokes the token; deactivation and password changes revoke all earlier tokens. OpenID Connect `sso_login` (`SSO_ISSUER`, `SSO_AUDIENCE`, `SSO_JWKS_URL`; IdP `amr` decides MFA). `list_access_report` covers logins and account, role and MFA changes. Processors confirm purges with evidence via `confirm_purge_status`; unconfirmed purges past `PURGE_COMPLETION_SLA_DAYS` are flagged to the DPO; a confirmed whole-account erasure de-identifies the CMS's own copy.
- **Logging (LG-02, LG-03):** login failures record the source IP; in-app notification dispatch is audited.
- **Out of scope:** BRD 4.2 Cookie Consent (CK-01..10), by decision.
- DB script: `18_brd_traceability.sql`. Dependency: `PyJWT[crypto]`.

### Upgrade notes

- **New database volume:** Compose applies all `db/*.sql` on first Postgres start — no extra steps.
- **Existing database:** Run `db/13` through `db/19` manually against the live DB (scripts are idempotent). See [README — Database upgrades](README.md#database-upgrades).
- **Environment:** Add `BOOTSTRAP_TOKEN` (min 32 characters) before starting the app or worker.
- **Rights portal:** Outside `local`, set each fiduciary's OTP mode to `EMAIL_OTP`/`MOBILE_OTP` with an `OTP` webhook, or set `ALLOW_DUMMY_OTP=true` for a demo — `DUMMY_OTP` logins are otherwise refused.
- **Roles:** Built-in DPO/OPERATOR/AUDITOR permissions are extended by `17`; review custom roles, which now need explicit `<resource>:<action>` grants for every admin function they call.
- **Audit ledger:** After `19`, `audit_logs` rejects UPDATE, DELETE and TRUNCATE for every role. Any maintenance job that edits or prunes audit rows must be retired first.
- **Process:** Run the background worker in production (`python -m dpdpcms_py.worker` or Compose `python_worker`).

### Not in repository

- MeitY BRD traceability workbook and internal findings documents are local-only (listed in `.gitignore`).
