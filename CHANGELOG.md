# Changelog

All notable changes in this branch are documented here for reviewers and operators upgrading from `origin/main`.

## [Unreleased] — P1/P2 Python port (branch `p1_changes`)

### Fixed (CMP API test run e01db1)

- **TC-N-13** `create_policy` and `update_policy` accept only `consent`, `legal_obligation`, `vital_interest` or `legitimate_use` as a purpose's `legal_basis` (400 otherwise), instead of a 201 or a CHECK-violation 500.
- **TC-39 / TC-N-19** `erasure_request` returns `purge_requests`: each request's `purge_request_id`, `purpose_id`, `status` (`PENDING` or `LEGAL_HOLD_APPLIED`), `legal_reference` and `hold_until`. `retained_under_legal_hold` entries also carry `hold_until`.
- **MFA** The first successful `verify_mfa` on an account revokes its sessions issued before MFA was on (they carried `mfa=true` from a password-only login). Clients switch to the token `verify_mfa` returns. Later MFA sign-ins revoke nothing.
- **TC-N-27** The external-nginx snippet printed by `install-helper/07-nginx.sh` and the install-helper README include `server_tokens off`.

### Fixed (P16 — workbook revision 17)

Migration `37_p16_remediation.sql` (idempotent) and:

- **P16-01** A console operator's `withdraw_consent` or `erasure_request` is audited with `initiator` `OPERATOR:<operator id>` and service type `DPO_CONSOLE`, not `INTEGRATOR`/`APP`. The operator must give a `grievance_reference` of the same fiduciary or a `reason` of at least 10 characters recording the principal's instruction (400 otherwise, before anything is written); the reference and grievance id are kept in the audit row. The DPO console asks for one instead of sending a fixed reason. API-key and principal withdrawals are unchanged.
- **P16-02** `db/32` no longer drops the append-only triggers of `audit_logs_legacy_pre32`; `db/37` puts them back on databases already upgraded, revokes the tenant reader from it, and seals its row count and chain head in `audit_legacy_ledger_seal`. The worker sweep `audit.verify_legacy_ledger` recomputes that table's chain weekly against the seal and records the verdict in `audit_legacy_ledger_verifications` (both append-only); `verify_audit_chain` reports the latest verdict to a global operator.
- **P16-03** Principal ids inside `alerts.payload` and `webhook_deliveries.payload` are stored sealed (`<key>_enc` ciphertext + `<key>_hmac` lookup HMAC, at any depth), opened only by `list_alerts` and the webhook dispatcher. Erasure re-seals them to the erasure token. The sweep `jobs.seal_queued_payloads` seals rows queued before this change. The webhook payload floor accepts only erasure or sealing of a principal key.
- **P16-04** Principal lookup HMACs (`<col>_hmac`, sealed payload HMACs, certificate `principal_id_hmac`) are keyed by the new `PII_LOOKUP_KEY`, separate from `DB_ENCRYPTION_KEY`. Production refuses to start without a distinct one; elsewhere it falls back to `DB_ENCRYPTION_KEY`. `python -m dpdpcms_py.rekey_lookup` recomputes every stored lookup HMAC under the current key. Certificates now record which key made their subject HMAC, so those issued before keep verifying.
- **P16-05** `reveal_user_id` also stops at 200 reveals per operator per rolling 24 hours (429). `jobs.flag_security_anomalies` raises a `SECURITY_PII_REVEAL_VOLUME` alert and DPO notice when one operator reveals 50 or more identifiers in a tenant within 60 minutes, once per window. The pen test gains `pentest/test_pii_reveal.py` (role, tenant, credential type, method and rate).

### Added (P15 — principal-identifier encryption, audit archiving, DPO reveal)

Ported from the Consent-Manager reference implementation. Migrations `31`-`36`, in order:

- `31_grievance_channel.sql`: `grievances.channel` (`PORTAL` default, `EMAIL`, `PHONE`, `LETTER`, `IN_PERSON`, `OTHER`); only console callers may set a non-PORTAL value.
- `32_partition_audit_logs.sql`: `audit_logs` becomes a table partitioned by year, with a default partition so a row dated in an unplanned year never fails. The previous table is kept as `audit_logs_legacy_pre32`, append-only (P16-02); its rows are not copied (ledger reset).
- `33_audit_archive_registry.sql`: `audit_log_archive_registry`. The worker sweep `archive_audit_partitions` detaches yearly partitions older than `AUDIT_LIVE_YEARS` (default `3`: the current year and the two before) into `audit_logs_y<YYYY>_archive` tables. Nothing is deleted, and verification, search and certificates still read archived years.
- `34_principal_pii_encryption.sql`: every principal identifier column becomes `<col>_enc` (pgcrypto, base64) plus `<col>_hmac` (HMAC-SHA256 of the trimmed value, case kept); the plaintext columns are dropped and keys are rebuilt on the HMAC columns under the same names. If rows exist and `app.enc_key` is unset the file raises before changing anything.
- `35_evidence_ip_encryption.sql`: guardian `verification_ref_id` and `proof_metadata`, `consent_records.ip_address`, and `audit_logs.source_ip` are stored encrypted; the claimed IP in `client_metadata` is stored as `ip_address_enc`. `tsi_audit_source_ip()` decrypts audit IPs for console reads and passes pre-35 plaintext through.
- `36_pii_reveal_permission.sql`: the `pii:reveal` permission for the DPO role.

New and changed endpoints:

- Admin `pii` service: `reveal_user_id` (DPO for their own fiduciary, ADMIN for any; permission `pii:reveal`; never by API key or principal token; 20 reveals per operator per rolling 60 s, then 429; the `PII_REVEALED` audit row is committed before the plaintext is returned).
- Consent: `get_consent_audit_trail` (needs `audit:read`, logs `AUDIT_LOG_READ`), `get_parental_verification` (guardian verification details for DPOs), `list_consent_history` accepts `user_ref` for console callers, `list_principals` returns `user_ref`.
- Grievance: `submit_grievance` accepts `channel`; the console can log a grievance received by another channel.

Behaviour changes operators must know:

- Console responses mask principal identifiers and return no consent IP to operators. Plaintext goes only to API-key callers on their own fiduciary, PURGE-scope processors on purge reads and `confirm_purge_status`, processor webhooks and alerts, and a principal exporting their own history.
- Audit `details` keep their key names but store each principal-valued key as its pseudonym (the same `TSI_LOOKUP_SALT` HMAC as `audit_logs.user_id`, which is unchanged); job `input_payload` stores principal keys as `<key>_hmac`.
- API response shapes: `_enc` and `_hmac` fields are never returned, principal identifiers are masked for console operators, and consent IPs are `null` for operators (shown only through a logged reveal). Integrations that read those fields must be updated.
- Principal identities now depend on `DB_ENCRYPTION_KEY`. Losing the key makes every principal unattributable. Do not rotate it once data exists: rotation needs re-encryption of every `_enc` column and a rebuild of every `_hmac` column (consent records only under the consent maintenance opt-in), audit IPs are append-only and stay readable only with the old key, and certificates issued before rotation fail live subject verification (see `docs/security/KEY_MANAGEMENT.md`).
- Env: `AUDIT_LIVE_YEARS` (default `3`, minimum `1`).
- Console: DPO audit trail and guardian details, per-purpose revoke, and a logged reveal control on the principals page.

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

- Unit tests under `python_port/tests/` (575 tests: P1/P2 helpers, SSRF, TOTP, roles, retention, a regression test per open defect in `test_defect_fixes.py`, BRD traceability rules in `test_brd_traceability.py`, the workbook v4 defects in `test_review_v4_fixes.py`, the workbook v5 defects in `test_review_v5_fixes.py`, the security-gap fixes in `test_security_gaps.py`, the workbook v10 findings in `test_p12_remediation.py`, the workbook v11 findings in `test_p13_remediation.py`, the revision-17 findings in `test_p16_remediation.py`, the CMP API test run e01db1 findings in `test_cmp_run_fixes.py`, the automated pen-test findings in `test_pentest_findings.py`, the bugs found re-verifying the BRD sheet in `test_brd_v5_bugs.py`, and DB-backed regressions in `test_integration_db.py` that run against a real Postgres and skip without one).
- GitHub Actions: Ruff lint, compile/import smoke test, pytest, Docker build (see `.github/workflows/main.yml`).
- Local deployment scripts in `scripts/local/` (preflight, init-env, deploy, migrate, bootstrap-admin, smoke-test, manage), in PowerShell (`.ps1`) and bash (`.sh`, for Linux, macOS, Git Bash and WSL), and the plan in `docs/LOCAL_DEPLOYMENT.md`.
- `docker-compose.yml`: the exports volume and `TSI_EXPORT_PATH` are fixed at `/var/lib/tsi/exports/` inside the containers. A relative `TSI_EXPORT_PATH` in `.env` (meant for native runs) used to break `docker compose up`. The app and worker now also load `.env` via `env_file`, so optional settings (DigiLocker, SSO, attachment limit, DUMMY_OTP opt-in) reach the containers.

### Changed

- `db/04_gaps.sql`: guarded encryption backfill when `app.enc_key` is not set (fresh init safety).
- Audit logging: discrete `purpose_id`, `consent_status`, `initiator`, `source_ip` columns where applicable (LG-02/03).
- Setup UI sends `bootstrap_token` with initial admin creation.
- Jobs: `create_job` now rejects an `input_payload` that is not a JSON object or array with 400 (free text could carry a principal id); principal-id keys inside it are stored as `<key>_hmac`.
- Evidence certificates: new certificates sign `principal_id_hmac` instead of the plaintext `principal_id`; the viewer shows the decrypted subject (masked for console operators). Certificates signed earlier keep verifying. A certificate whose subject was erased still verifies its signature, trail and chain and reports `subject_erased: true`.
- Guardian evidence and the consent session IP are stored encrypted (`db/35_evidence_ip_encryption.sql`: `parental_verification_logs.verification_ref_id_enc`, `.proof_metadata_enc`, `consent_records.ip_address_enc`); erasure writes the encrypted `0.0.0.0`. The IP an integrator claims is kept in `client_metadata` only as `ip_address_enc` (existing rows converted by db/35; erasure overwrites it with the encrypted `0.0.0.0`). Consent reads never return the ciphertext: API-key and principal callers get the decrypted `ip_address` (and claimed `client_metadata.ip_address`), console operators get `null`.
- Audit ledger: principal ids inside `context_details` (any key in `audit.PRINCIPAL_DETAIL_KEYS`, at any depth) are stored as their pseudonym; the row `user_id` pseudonym ignores surrounding spaces; a new row's `source_ip` is stored encrypted (the hash covers the ciphertext) and console audit reads show it decrypted. Rows written earlier are unchanged.
- Admin `pii` service `reveal_user_id` (ported from Consent-Manager): a DPO (own fiduciary) or ADMIN holding `pii:reveal` (`db/36_pii_reveal_permission.sql` grants it to the built-in DPO role) sees one record's principal identifier in the clear - consent record (user id and session IP), grievance, purge request, data principal (by `user_id_hmac`) or guardian verification (guardian id and evidence). Every reveal writes a `PII_REVEALED` audit row (initiator `OPERATOR:<id>`, no plaintext) before the value is returned; 20 reveals per operator per rolling minute, then 429. Never reachable by an API key or principal token.
- Admin `consent` service `get_parental_verification` and `get_consent_audit_trail` (ported from Consent-Manager), console operators only, by `consent_record_id`. The first returns the guardian verification a minor's consent rests on with `guardian_id` and `verification_ref_id` masked and only `has_proof_metadata` for the proof (404 for an adult's record). The second (`audit:read`, itself logged as an `AUDIT_LOG_READ`) returns every ledger event, live and archived years, about that record or the records it supersedes, for the record's principal pseudonym and fiduciary, grouped by purpose (`ALL` when an event names none) with the purpose name and the data-category names it covers in the record's policy.

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

### Fixed (Security Gaps sheet, traceability workbook security)

- **SEC-01** The unauthenticated recovery path (`verify_recovery_key`,
  `reset_password_via_recovery`) is now throttled and locks out by email and by
  source IP, every attempt and success is written to the audit ledger, and the
  password floor matches `initial_setup` (12 characters). The reset also clears
  `last_login_at` so the takeover is visible from the login signal. New
  `auth_throttles` table (db/20), generic `throttle.py` helper, worker sweeps
  the expired rows.
- **SEC-03** Operator login now uses the same lockout pattern as MFA: 5
  failures by identifier or source IP lock the account for 15 minutes, both are
  cleared on success, and `last_login_at` is finally written on every
  successful login.
- **SEC-04** `confirm_purge_status` is bound to the authenticated caller. An
  API key must belong to the app assigned to the purge request (`app_id` now
  recorded when an erasure is initiated through an integrator key); the
  confirming identity is derived from the credential, never from the
  `confirmed_by_entity_id` body field, and the processor's claimed record count
  is stored separately from CMS-verified erasure counts. Tests cover the 403 /
  pass paths.
- **SEC-05** `link_user` no longer accepts `age_category`, `verification_status`
  or `guardian_id`, and never lets an upsert default overwrite an existing
  value: only records are relinked and a server-attested profile is carried
  across. `record_consent` no longer defaults a silent age to ADULT either, and
  the EXISTING_ACCOUNT guardian path requires an explicitly-ADULT profile row.
- **SEC-06** `get_admin_metrics` is tenant-scoped for DPO/OPERATOR/AUDITOR
  callers (platform-wide only for a global ADMIN), matching `get_dpo_metrics`.
- **SEC-07** `api_key_valid` refuses keys whose `expires_at` has passed, and a
  new worker sweep (`expire_lapsed_api_keys`) marks lapsed keys EXPIRED so the
  listing and the enforced behaviour agree.
- **SEC-08** The no-escalation check on custom roles now runs for every actor,
  including a global one with a NULL `fiduciary_id`: a role:manage holder
  without full access can no longer mint a global role carrying `"*"`.
- **SEC-10** Evidence certificates are signed (HMAC-SHA256 with
  `certificate_signing_key`, defaulting to the DB encryption key) and carry
  environment metadata and a verifiable evidence trail; the DPO console posts
  `subject_principal_id` (the form previously always 400'd) and the audit page
  gains a "Verify Chain Integrity" button that surfaces `verify_audit_chain`.
- **SEC-12** `deactivate_user` and the sibling deletes (`delete_app`,
  `delete_policy`, `delete_fiduciary`, `retire_entry`,
  `delete_retention_policy`, `revoke_nomination`) check the rowcount and 404 on
  zero before reporting (or logging) success.
- **SEC-13** The principal OTP is encrypted at enqueue (pgcrypto) and rendered
  plaintext only at dispatch, so `webhook_deliveries.payload` never rests in
  the clear; a worker sweep enforces retention on terminal `webhook_deliveries`.
- **SEC-14** An unconfigured rights app reads EMAIL_OTP instead of DUMMY_OTP,
  recording DUMMY_OTP is refused outside `ALLOW_DUMMY_OTP`, SSO logins require a
  single-use nonce (replay of a captured id_token fails), and the JWKS client
  is cached per URL instead of fetched on every login.
- **SEC-15** `erase_cms_copy` now covers every table carrying a principal
  identifier: nominations (both columns), data-correction requests,
  re-consent requests, parental-verification logs (both columns), PRINCIPAL
  alerts, notification deliveries (via the owning notification) and affected-
  principals breach rows, exposed as `ERASURE_TARGETS` with a regression test.
- New `db/20_security_gaps.sql` (throttles, SSO nonces, OTP-mode default) and
  `python_port/tests/test_security_gaps.py` (30 tests) covering the above.

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

### Fixed (Security workbook v2, defect-remediation round 2, branch `p6_defect_fixes`)

- **P5-01 / SEC-15** Erasure ordering fixed in `erase_cms_copy`: the grievance
  attachment DELETE and the text-blanking UPDATE run before the generic
  `ERASURE_TARGETS` loop (whose re-keying once made both predicates match
  nothing), grievances are skipped inside the loop, and `resolution_details` is
  blanked too. The remaining SEC-15 survivors are now scrubbed:
  `evidence_certificates.subject_principal_id`, `data_principal.guardian_id` on
  other principals' rows, `consent_records` session metadata, and the raw
  `user_id` inside `alerts.payload` and `webhook_deliveries.payload`. The
  tautological coverage test was replaced with one that executes
  `erase_cms_copy` and asserts the statement ordering.
- **SEC-17** Schema validation now runs on GET as well as POST, and GET is
  restricted to read-classified functions (405 for a write over GET). The admin
  auth path no longer reads `?auth=` from the query string, so a credential can
  never sit in a URL, browser history or proxy log.
- **SEC-05** The s.9 gate reads the *stored* `age_category` in
  `record_consent`: a stored MINOR stays a minor when the body is silent,
  declaring ADULT for a stored MINOR is refused, and a VERIFIED guardian log is
  required whenever the effective age is MINOR.
- **P5-02** The throttle counter decays: observing a lapsed lock (or a
  saturated counter) starts a fresh window, and locks escalate geometrically
  (15m → 30m → 60m cap). X-Forwarded-For is honoured only behind a configured
  `TRUSTED_PROXY_IPS`, so reverse-proxied operators each get their own bucket.
- **P5-03 / SEC-01** Account throttle keys are the deployment-key HMAC of
  `lower(trim(email))` (`throttle.email_key`), never the raw address; the
  normalisation variants share one bucket.
- **P5-04 / SEC-04** The purge app-binding falls back when a request has no
  initiating app (closure/sweep/console/principal erasures can again be closed
  by the tenant's processor), and a request delegated to a specific operator is
  bound to that operator, for API keys and console callers alike.
- **SEC-18** `create_user` refuses a non-ADMIN role without a `fiduciary_id`,
  closing the NULL-fiduciary account shape that defeated tenancy checks.
- **P5-06** `create_nomination` omits `valid_from` so the `DEFAULT NOW()`
  applies; omitting the field no longer 500s.
- **P5-07** `webhook_deliveries` is treated as a Rule 6(1)(e) access log: the
  terminal-row retain floor is 365 days (`WEBHOOK_DELIVERY_RETENTION_DAYS`),
  not a hard-coded 30. See design decision DD-05.
- **SEC-13** `db/21` adds a one-off DELETE of pre-encryption webhook rows whose
  payload still carries the plaintext `otp`, so the raised retention floor does
  not preserve codes from before the fix.
- **SEC-10** Generation and verification share `audit.certificate_signature`;
  `generate_certificate` verifies the chain it embeds and refuses (409) to sign
  a tampered ledger; new `verify_certificate` recomputes the HMAC;
  `verify_chain` walks newest-first (recent tampering cannot hide outside the
  limit) and accepts a tenant scope, so a tenant-scoped DPO verifies its own
  ledger.
- **SEC-12** `update_user` now honours the rowcount pattern (404 on zero).
- **CF-02 / SEC-11** `tour/consent-verifier.html` and
  `tour/parent-consent.html` carry the `esc()` helper and escape all API data.
- **P4-01** The wallet's `GET_POLICY_PURPOSES` (accepts `policy_id`, serves
  `purposes`/`policy_title`/`personas`) and `GET_CONSENT_DETAILS` (accepts
  `policy_id`, resolves the principal's active record) no longer 400 on the
  fields the client actually sends.
- **CF-03 / CF-04** CHANGELOG test count corrected to 205; the README upgrade
  loop and table list `db/20` and `db/21` (`13`–`21`).
- **CF-05** Cookie/tracker consent decided: only strictly-necessary cookies are
  set; BRD 4.2 is read Not applicable via DD-04.
- **P5-05** The security findings workbook was removed from the repository,
  `*.xlsx` is gitignored, and the file was purged from local history.
- New `db/21_defect_remediation_p6.sql`.

### Fixed (Security workbook v3, remediation round on `p6_defect_fixes`)

Closes every previously-OPEN finding from the security workbook's third
revision. Where a finding said "PARTLY FIXED" the remaining half is now closed;
where it said "OPEN" the defect is fixed.

- **P6-01 / LG-04** `verify_chain` no longer scopes the *query* — the chain is
  global (a row's predecessor is picked with no fiduciary filter), so filtering
  the rows before checking adjacency reported LINK_MISMATCH on an intact
  ledger. It now walks the unfiltered chain and filters only the *report*:
  a tenant-scoped DPO gets back only its own counts and broken-row ids, and an
  untampered ledger verifies as intact. A break in another tenant's rows is
  never attributed to — or leaked to — the caller.
- **P6-02 / UD-02** The `policy_id` branch of `get_consent_record_details` now
  requires and binds `user_id` (principal JWTs get it from the token; API keys
  must name a principal). A READ-scoped key can no longer read an arbitrary
  principal's active consent record without naming them. The response also now
  carries each purpose's lifecycle state and governing retention, so the
  dashboard shows the DD-01 substitute for an expiry date.
- **P6-03 / LG-07** Console export downloads are fixed without bringing back
  `?auth=` in a URL: `download_file` returns the file's bytes base64-encoded in
  the authenticated JSON response, and the admin dashboard and DPO reports
  pages fetch it with the Authorization header and hand the browser a blob.
- **P6-04** `record_failure` issues the counter increment server-side in one
  atomic `INSERT ... ON CONFLICT ... RETURNING` (a parallel burst of first
  failures can no longer all write 1); the lock decision is then applied from
  the returned row in the same transaction. `client_ip` now walks the
  X-Forwarded-For chain right-to-left dropping trailing trusted hops — a caller
  cannot force a spoofed hop at the front of the header to win — and
  `TRUSTED_PROXY_IPS` matches CIDR ranges as well as literals.
- **P6-05** `_is_read_classified` now folds in client-category READ scopes, so
  `validate_consent` and `sync` (both READ for client callers) are no longer
  refused a GET.
- **P6-06 / SA-13** The erasure ordering bug is dead for good: in
  `erase_cms_copy`, the `consent_records` metadata scrub and the
  `notification_deliveries` join now run BEFORE the generic re-key loop (which
  matches the grievance block from P5-01), so the session IP / user agent and
  the delivery recipient really are scrubbed.
- **P6-07** `create_nomination` binds `COALESCE(%s, NOW())` for `valid_from`,
  so a caller-supplied future effective date is honoured instead of silently
  discarded (a missing value still falls back to `DEFAULT NOW()`).
- **P6-08** `tour/parent-consent.html` keys the checkbox lookups off a JS map
  rather than building a `getElementById` string from escaped markup, so a
  purpose id containing an entity character no longer breaks the submission.
- **P6-09** The one-off OTP cleanup in `db/21` is restricted to terminal
  `webhook_deliveries` rows — a principal who requested a code just before the
  migration ran still receives it.
- **SEC-04** `erasure_request` through an integrator key is bound to a real
  principal: a key may no longer open a purge for a user the fiduciary holds no
  consent record on, closing the WRITE+PURGE escalation that reached
  `erase_cms_copy` for an arbitrary user_id.
- **SEC-10** `verify_certificate` compares the signature in constant time,
  re-derives the embedded trail against `audit_logs` (hashes that no longer
  exist invalidate the certificate), and refuses a certificate resting on a
  chain that no longer verifies. The DPO console's legal page gains a
  "Verify Integrity" button.
- **SEC-18** `update_user` only touches `fiduciary_id` when the caller
  explicitly supplies a tenant, and refuses NULL for non-ADMIN rows — an ADMIN
  rename that omits the field no longer silently nulls the operator's tenant.
  New `db/22_sec18_null_fiduciary_block.sql` deactivates pre-existing
  non-ADMIN operators with a NULL `fiduciary_id` (the account shape that
  defeats every tenancy check).
- **PL-03** The CMS finally reads `purge_requests.action`: ERASE deletes the
  `data_principal` profile, DE_IDENTIFY re-keys it to the pseudonym, so the two
  dispositions no longer behave identically.
- **GR-07** The overdue-grievance sweep notifies the fiduciary's DPO as well as
  the complainant.
- **P5-07** `prune_old_webhook_deliveries` enforces the Rule 6(1)(e) one-year
  floor whatever `WEBHOOK_DELIVERY_RETENTION_DAYS` says, and the never-prune
  policy for `audit_logs` / `notification_deliveries` is stated as policy
  (RULE_6_1_E_MIN_RETENTION_DAYS), not a code accident.
- Tests: `test_security_gaps.py` grows regression coverage for every P6-xx /
  SEC residual above (scoped chain, policy_id user_id, right-to-left proxy,
  GET reads, erasure ordering, valid_from, DPO escalation notice, retention
  floor, migrations); `test_defect_fixes.py` stubs every sweep the worker now
  runs so the isolation test no longer waits on a dead database connection.
- Still OUTSTANDING (not code): **P5-05** — the findings workbook blob remains
  public on the published `p5_changes` branch; deleting or rewriting that
  branch is an owner action that needs remote push access. `D10/D13` remain
  bookkeeping only — reconciling the two p3 defect letters requires the original
  p3 defect list.

### Fixed (Security workbook v6, p7 remediation round)

Independent re-review against `951bad4` found four NEW defects and, correctly,
that several v4-era "FIXED" labels were premature. All are now closed:

- **P6-10** Reverts part of the P6-05 GET widening: client READ scopes fold into
  `_is_read_classified` only via a curated `CLIENT_GET_SAFE_FUNCS` set. 
  `validate_consent` — stamped READ but WRITES (inserts a validation row,
  notifies the principal) — is explicitly excluded, so SEC-17's GET boundary is
  restored. Regression test pins both directions.
- **P6-11** CI triggers are no longer a per-branch allow-list: the workflow runs
  on `push` to every branch and on every `pull_request`. The
  "CI silently disabled because a branch name changed" class is gone.
- **P6-12** Certificate verification/generation no longer pull up to 2,000,000
  unfiltered rows into the API process: the trail is re-derived from the
  certificate's own hashes and the global chain check is bounded
  (`WINDOWED_CHAIN_CHECK_ROWS = 100_000`).
- **P6-13** `verify_chain` reports in-scope total / verified / legacy separately
  (`rows_checked` / `rows_verified` / `legacy_rows_linkage_only`), so a tenant
  DPO's figure is comparable with the ADMIN-scope figure.
- **SEC-04** finally closed. The whole-account erasure escalation is dead: a
  purge row a key opened (app_id + `ErasureRequest` purpose ALL) can only be
  confirmed by an operator, never the same (or any) API key. Purpose-scoped
  purges stay processor-confirmable. Regression test covers the block.
- **SEC-10** Signature comparison is constant-time and byte-coerced (a tampered
  non-ASCII signature reads INVALID, never 500); the embedded trail is
  re-derived against the live ledger including ORDER and completeness, not just
  existence. Three regression tests.
- **SEC-18** Runtime fails closed: `authenticate` refuses a non-ADMIN operator
  with a NULL `fiduciary_id` at the door (403), so the shape is blocked the
  moment it recurs — db/22 remains as the cleanup of pre-existing rows.
- **P5-07** The one-year floor is database-enforced on `notification_deliveries`
  too: db/23 adds a BEFORE DELETE trigger (mirrors audit_logs in db/19), so a
  direct DELETE can no longer bypass the policy.
- **P6-07** Nomination dates now have effect: `create_nomination` stores PENDING
  when `valid_from` is in the future; `list_nominations` computes an effective
  status and filters on it; a new `expire_nominations` worker sweep flips
  ACTIVE → EXPIRED past `valid_until`.
- **PL-03** Purpose-scoped purges de-identify the CMS copy:
  `deidentify_purpose_cms_copy` blanks (DE_IDENTIFY) or drops (ERASE) the
  purpose from consent_records when a purpose-closure/retention purge completes.
- **GR-07** Category routing: `submit_grievance` auto-assigns to the fiduciary's
  ACTIVE DPO and marks IN_PROGRESS, notifying the DPO.
- **UD-02** The rights dashboard now renders each purpose's lifecycle state and
  retention period (the DD-01 expiry substitute) from `purpose_states`.
- **CF-03** Regression coverage added for every p6/p7 finding (download path,
  tour page, SEC-04 block, SEC-18 refusal, effective nomination status, CI
  triggers, bounded cert verification, scope reporting); suite is 252 tests.
- New `db/23_notification_delivery_floor.sql`. README upgrade list extended to
  `db/13..23`.
- **Still open (not code):** **P5-05** — workbook blob still public on
  `origin/p5_changes`; **D10/D13** — reconciled as far as evidence allows (D13 =
  README loop / CF-04, Fixed), D10 awaits the p3 list.

### Fixed (Security workbook v5, p8 remediation round)

Independent re-review against `85f515f` found six new defects (P7-01..P7-06).
All are closed, and the root cause the workbook names — the suite stubs the
database — is being addressed with a real-Postgres CI path.

- **P7-01 (CRITICAL)** `deidentify_purpose_cms_copy` now takes `user_id` and
  both UPDATEs scope by it, so a purpose-scoped purge completion de-identifies
  only the principal whose purge completed — never every consent record in the
  tenant. The legal-hold guard now applies to this branch too. The old test
  that monkeypatched this exact function away (and asserted no arguments) is
  replaced by one that pins the call-site `user_id` and one that inspects the
  emitted SQL for `user_id = %s`.
- **P7-02** The chain verifier no longer reports "intact" when a scoped DPO's
  rows fell outside the window: `verify_chain` returns `unexamined_tenant`, and
  `verify_certificate` / `generate_certificate` refuse (invalid / 409) rather
  than certify an unexamined chain.
- **P7-03** Nomination status derivation short-circuits terminal statuses
  (REVOKED, EXPIRED) in both the SQL filter and the Python loop; `status` stays
  as stored and the derived value lives in `effective_status` — a revoked
  nomination can never read "PENDING".
- **P7-04** db/23 gains BEFORE TRUNCATE triggers and the same floor trigger on
  `webhook_deliveries`; `UPGRADE_MIGRATIONS`, `migrate.sh`, `preflight.sh` and
  `deploy.sh` now cover db/21..db/23 (deploy.sh "01-23").
- **P7-05** Grievance routing to a DPO now emits a DPO notification (the
  assigned DPO is told, not just the principal) and no longer forces
  IN_PROGRESS in the same call, so the console's NEW state stays observable.
- **P7-06** `get_consent_record_details` now reads the retention day count from
  the governing retention policy / ROPA (never an ISO `consent_expiry`
  mislabelled as a period) and reports the lifecycle state verbatim
  (OPEN/CLOSED); the rights dashboard renders the badge against CLOSED and
  labels the span "retention N days".
- **Root cause: real Postgres in CI.** The test job now provisions a Postgres
  service, applies `db/*.sql`, and runs the suite against it. New
  `tests/test_integration_db.py` exercises the P7-01 scoping, P6-06 erasure
  ordering and the chain verifier against the live ledger; they skip when no DB
  is reachable so the local unit suite stays fast. This is the fix the workbook
  named as the reason each branch closes findings and opens new ones.
- Tests: 260 passed, 4 skipped (3 DB-backed + 1 pre-existing); ruff clean. First CI
  run against the live Postgres surfaced fixture faults in the DB tests themselves
  (`language_selected` NOT NULL, the consent_records FK parents, `UPDATE ... ORDER
  BY ... LIMIT 1` not being valid PostgreSQL, and the db/19 append-only trigger
  blocking the tamper step). The fixtures now seed the FK parents with per-test
  policy ids, tamper via a trigger-disable, and query with `dict_row`. Locally
  validated against a fresh postgres:16: 263 passed, 1 skipped.

### Fixed (Security workbook v6, p9 remediation round)

Re-review against `b0bb35c` (workbook v6) left two blockers (P8-01, P8-02), six
further P8 findings, and residuals on P7-02..P7-06, SEC-10 and P6-12. All are
closed in code and each has a DB-backed regression test that runs against the
real schema.

- **P8-01** `deidentify_purpose_cms_copy` DE_IDENTIFY branch casts the pseudonym
  marker (`%s::text`) so `jsonb_build_object` no longer raises
  `IndeterminateDatatype`. Covered for the one principal, a second principal and
  a second tenant, and end to end from purpose closure through the retention
  sweep to the purge confirmation (PL-03).
- **P8-02** The legal-hold refusal for a purpose-scoped purge is evaluated
  BEFORE the status UPDATE, so a held request is no longer recorded
  PURGE_COMPLETED with nothing de-identified and no audit event. The request's
  own (expired) hold row is excluded so it cannot block itself.
- **P8-03** db/23 drops its previous version's trigger
  (`notification_deliveries_floor`) and function
  (`enforce_notification_delivery_floor()`), so re-applying it leaves exactly the
  current triggers. Deleting a young `notifications` row now fails with a message
  naming the real cause (db/24) instead of raising from the cascaded table.
- **P7-04 residuals** db/24 adds BEFORE UPDATE floors: inside the one-year floor
  `notification_deliveries.recipient` and `webhook_deliveries.payload` may change
  only to the erasure pseudonym (`erased:...`), and the identity columns are
  immutable. `migrate.sh` now verifies all seven Rule 6(1)(e) floor triggers and
  the absence of the pre-rename trigger, so a partial install fails.
- **P7-02 / P8-04** `verify_chain` reports `coverage_complete`,
  `rows_in_scope_total` and `rows_unexamined`; a truncated window is measured
  against the scope's real row count instead of the unreachable
  `rows_checked < 1` test. Certificate generation and verification anchor the
  walk on the certificate's own oldest trail entry (`since=`), examine every row
  from there to the head, and refuse rather than certify when that walk is
  incomplete. The anchored walk also checks the anchor row's link to its
  predecessor.
- **SEC-10** Linkage and content are verified on the unfiltered chain and a
  break in another tenant's rows now makes a scoped result not intact (reported
  as `foreign_broken_count`, without the other tenant's ids). `verify_certificate`
  compares the trail against the principal's actual ledger for the period it
  covers, so an omitted event invalidates the certificate.
- **P6-12** New index `idx_audit_logs_chain_order (timestamp DESC, id DESC)` (built CONCURRENTLY; do not run db/24 with `psql -1`)
  removes the Seq Scan + Sort. The full-ledger walk moves to a once-a-day worker
  sweep (`audit.record_chain_verification`, table `audit_chain_verifications`),
  and `verify_audit_chain` reports its latest verdict as `last_full_verification`.
- **P8-05** The DPO console tells "not verified" (no rows of yours in the
  window), "verified but incomplete" and "broken outside your records" apart
  from "verified broken", and shows the last full-ledger check.
- **P8-06** DB-backed tests run inside one transaction that is rolled back, so
  seeded rows and the tamper step no longer leave the shared database dirty.
- **P8-07** Retention periods for every purpose on the consent dashboard are
  resolved in two queries (`services.retention.retention_for_purposes`), and
  request handlers no longer import the private helper from `jobs`.
- **P7-03 residual** The Python effective-status derivation uses the SQL
  filter's precedence (valid_from before valid_until), so a row is reported with
  the status it was selected by.
- **P7-05 / GR-07** `assign_grievance` no longer forces IN_PROGRESS (both
  assignment paths now leave the status as is) and notifies the assignee. The
  assignee's notice is a new officer-facing type, `GRIEVANCE_ROUTED`, that
  carries the grievance reference and category through the new
  `notifications.context` column. Category routing to a department: new admin
  functions `set_grievance_routing` / `list_grievance_routing` and table
  `grievance_routing_rules`. A category without a rule falls back to the DPO,
  and `grievances.department` records where the grievance went.
- **SA-13 residual** New worker sweep `prune_old_notification_deliveries`
  (`NOTIFICATION_DELIVERY_RETENTION_DAYS`, never below the one-year floor) gives
  `notification_deliveries` a retention policy.
- **NT-03** Principal notifications are rendered in the language the principal
  last chose (the template's text for that Eighth Schedule code, else English).
- **CF-03** Extended DB coverage: DE_IDENTIFY, a second tenant,
  `_set_purge_status`, the db/23 and db/24 triggers and their idempotency,
  certificate anchoring and completeness, and the index plan.
- New `db/24_p8_remediation.sql`, added to `UPGRADE_MIGRATIONS`, `preflight.sh`,
  `deploy.sh` (01-24) and the README.
- Review follow-ups. The notification backfill skips notifications older than
  the delivery retention, so pruned deliveries are never re-sent. A malformed
  template can no longer abort a delivery batch. The daily chain-verification
  claim is released if the walk fails. The ERASE branch keeps consent entries
  that carry no purpose id. An expired hold no longer blocks purpose
  de-identification. `set_grievance_routing` needs `operator:write`, and the
  officer must hold `grievance:write`. Certificates record `trail_truncated`,
  and verification rejects a trail that leaves out earlier events without
  declaring truncation. The chain index is built `CONCURRENTLY`.
- **Legal-hold race** `_set_purge_status` now runs the hold checks, the status
  UPDATE and the CMS de-identification (`erase_cms_copy` /
  `deidentify_purpose_cms_copy`, which accept the caller's cursor) in ONE
  transaction. The transaction holds a per-principal advisory lock
  (`lock_principal_purges`) and locks the request row with `FOR UPDATE`.
  `erasure_request` takes the same lock first, before any row lock, so the two
  paths cannot deadlock. A hold written concurrently is either seen by the
  check or waits for the purge to commit; it can no longer land between the
  check and the erasure. A refusal rolls back, and attachment files are removed
  only after the commit. The whole-account path now also ignores expired holds,
  as the purpose path does. A two-connection test proves the confirmation waits
  for an in-flight hold and then refuses.
- **D10 / D13 reconciled** against the p3 defect list
  (`MeitY_BRD_API_Traceability_v4.xlsx`, Defect Remediation, rows 10 and 13).
  D10 ("CHANGELOG claims tests that do not exist; CI skips pytest") is fixed:
  CI runs pytest unconditionally, and the stale "205 tests" claim is corrected
  to the collected 287. D13 ("README upgrade loop omits db/17 and db/18") is
  fixed: the README loop and `UPGRADE_MIGRATIONS` list `db/13..24`. New guard
  tests fail if the CHANGELOG's count or file names drift from the suite, if CI
  regains a skip, or if a migration is missing from the scripted upgrade list.
- **Re-review follow-ups (race fix):**
  - The per-principal lock key normalises the fiduciary UUID, so a payload-cased
    id and the DB-cased id share one lock.
  - The SEC-04 app/operator binding is re-checked on the locked row. A request
    reassigned while the update is in flight now gets 409 instead of being
    closed by a key it no longer belongs to.
  - Every withdrawal, not only an erasure, takes the lock before any
    `consent_records` row lock, so no lock-order deadlock remains.
  - A whole-account completion kept by another hold is now recorded in the
    audit trail (`cms_erasure_deferred_by_legal_hold`).
  - `erase_cms_copy(cur=...)` requires `pending_files`.
  - `set_grievance_routing` deletes only on `remove: true`, and
    `assign_grievance` applies the same `grievance:write` officer check.
  - Legacy certificates without `trail_truncated` are not failed by the
    below-anchor check.
  - The daily chain-verdict insert is inside the claim-release `try`.
  - db/24 drops an INVALID leftover from an interrupted CONCURRENTLY build.
  - The DB test fixture uses a savepoint per block.
  - The race test joins its thread before cleanup.
  - The D10 count guard runs only on an unfiltered run of every test file.
- **P5-05 closed.** The `origin/p5_changes` history was rewritten to drop
  `MeitY_BRD_API_Traceability_security.xlsx` (tip `07f1179` -> `365a9d3`, tree
  unchanged, now-empty delete commit pruned) and force-pushed with lease. No
  other branch or PR ref ever contained it. GitHub still serves the
  unreferenced commit `d096530` by SHA from its cache until GitHub Support
  purges it.
- Tests: 292 passed, 1 skipped (293 collected) against a fresh postgres:16 with
  `db/01..24` applied. The database is empty after the run. ruff check clean.
- **Known limits (performance, not correctness):** `verify_chain` holds the
  walked window in memory: up to 1M rows for a certificate anchor, and the
  ledger cap for the worker's daily walk. Streaming it in keyset batches is the
  next step for very large ledgers.

### Fixed (Security workbook v7, p10 remediation round)

Re-verification of all 120 requirements against `a3d9c58` (workbook v7) raised
eight new findings (P9-01..P9-08) and left four requirements off Exists
(SA-04, GR-08, GR-11, NT-05). All are closed in code; each has a DB-backed
regression test in `test_integration_db.py`.

- **P9-01 (CV-02)** `validate_consent` matches the CLOSED-purpose gate
  case-insensitively, as the grant matcher already did, so `marketing` no longer
  validates while `MARKETING` is closed. The closure holder query, the cessation
  lookup and the retention sweep match purpose ids the same way.
- **P9-02 (CU-05)** `check_consent_alignment` refuses (409) a policy version that
  is not ACTIVE with an effective date in the past — the version
  `get_active_policy` serves. DRAFT and ARCHIVED versions are rejected.
- **P9-03 (NT-05)** `mark_notification_read` audits the resolved id, so a caller
  using the schema's `id` field no longer gets a 500 and the
  `NOTIFICATION_ACKNOWLEDGED` row is written.
- **P9-04 (PL-02)** Reopening a purpose cancels the PENDING purges its closure
  or retention clock raised (new `CANCELLED` purge status, db/25) and resets
  `opened_at`, so a lapsed TIME_BOUND purpose is not re-closed on the next cycle.
- **P9-05 (CC-07)** db/25 makes `consent_records` append-only at the database
  level. UPDATE, DELETE and TRUNCATE fail, except the retirement flip
  (`is_active_consent` TRUE -> FALSE with only `last_updated_at` changing) and
  the sanctioned rewrites — erasure, purpose de-identification and the
  anonymous-session link — which opt in for their own transaction with
  `db.allow_consent_maintenance()`.
- **P9-06 (UD-02)** A principal's self-check from the dashboard no longer writes
  a validation row, a denial notice, a `CONSENT_DENIED` webhook or an audit
  entry. The dashboard reads `valid` and `metadata.purpose_status` (it read a
  `consent_granted` key the response never had) and shows withdrawn and closed
  purposes distinctly.
- **P9-07 (CW-06)** `withdraw_consent` with no active consent returns 404 and
  fires no notification, webhook, alert or audit event. An erasure request is
  still accepted after a full withdrawal.
- **P9-08 (LG-07)** The EXPORT/AUDIT CSV carries every hashed column,
  `prev_log_hash`, `current_log_hash` and `system_metadata`, and writes the
  chain verdict for the exported range beside it (`*.verification.json`). The
  console XLSX export adds the same columns.
- **SA-04** `update_user` applies `role` (same rules as `create_user`: known
  role for the tenant, only ADMIN grants ADMIN, a DPO assigns OPERATOR to
  OPERATOR accounts only) and `status` (ACTIVE/INACTIVE). A role change,
  deactivation or password change ends existing sessions. An omitted `username`
  no longer nulls the NOT NULL `name` column. A tenant-scoped caller cannot move
  an operator to another fiduciary.
- **GR-08** `list_grievances`, `get_grievance` and `list_user_grievances` return
  `grievance_id` alongside `id`, so the DPO queue and detail view render.
- **GR-11** The resolution notice carries the reference number and the
  resolution summary (notification context). Erasure clears that context with
  the rest of the grievance text.
- **GR-03** `submit_grievance` stores the principal's `language` (new column,
  db/25); the rights portal sends the selected language.
- **CW-04** The withdrawal modal calls `get_withdrawal_implications` and shows
  each purpose's consequence and any legal retention before the principal
  confirms.
- **NT-10** `record_alert` (every consent and purpose-closure alert) writes an
  `ALERT_RAISED` audit row, and the stale-alert sweep writes `ALERT_ESCALATED`.
- **SA-14** `delete_retention_policy` writes `RETENTION_POLICY_DELETED`.
- Tests: 307 passed, 1 skipped (308 collected) against a throwaway Postgres
  with `db/01..25` applied; db/25 re-applied cleanly.

### Fixed (Security workbook v8, p11 remediation round)

Workbook v8 re-verified `038f6ce` and raised eleven findings (P10-01..P10-11),
left P9-08 partly open and kept fourteen requirements off Exists. All are
closed in code, with a DB-backed regression test for each in
`test_integration_db.py`. The re-consent flow (P10-02) is now tested against
the real policy and ROPA rows, so CI no longer depends on unit tests that stub
the policy as ACTIVE (the CF-03 blind spot).

- **P10-01 (CC-03, CV-01, CU-05)** A consent decision is stored under
  `data_point_id` only. One that names two different purposes through two
  aliases (`purpose_id` and `id`) is refused with a 400. Every reader resolves
  the aliases in one order (`data_point_id`, `purpose_id`, `id`), which is the
  order the SQL in erasure, closure and retention already used.
- **P10-02 (CU-02, CU-03)** A version is activated when its ROPA is complete,
  and the re-consent notices go out only at activation, never while the version
  is UNDER_REVIEW. A wording-only change creates no new ROPA entry, so it
  activates at `publish_policy`. A version that adds a purpose activates when
  its last ROPA entry is published. `notify_policy_change` refuses (409) a
  version that is not active and in effect.
- **P10-03 (SA-03, SA-04)** Assigning a role is bounded by the caller's
  permissions, not its role name: the target role's permission set must be held
  by the caller. This is enforced in `create_user` and `update_user`. An
  operator cannot change its own role.
- **P10-04 / P10-05 / P10-09 (PL-03, PL-04, SA-09, SA-10, CW-11)** Purpose ids
  are canonical (trimmed, lower-case) on write:
  - The services canonicalise policy purposes, consent decisions, lifecycle rows,
    retention `applicable_purposes`, erasure targets and the ROPA link.
  - db/26 rewrites the stored rows once and adds canonicalising triggers.
  - Case-variant lifecycle rows are merged and the CLOSED one is kept.
  - Retention and legal-hold lookups resolve on the canonical id.
  - Reopening a purpose cancels only that purpose's purges raised since the
    closure, and only for principals whose consent to it is still active.
- **P10-06 (LG-04, LG-07)** `verify_chain` takes an exclusive `until` bound and
  checks the link from the window's newest row to its successor. The AUDIT export
  verdict is bounded by `start_date` and `end_date`, and `chain_intact` is true
  only when the chain is intact and coverage is complete. Otherwise
  `attestation` reads `NOT_ATTESTED` or `BROKEN`. The export's end bound is now
  exclusive, so it matches the verdict's window. `list_logs` returns
  `system_metadata`, and the console XLSX export carries it and `fiduciary_id`.
- **P10-07 (GR-11)** For any channel other than in-app, `render_message`
  replaces free-text context (the resolution summary) with a pointer to the
  app. The summary is never handed to the SMS or push gateway.
- **P10-08 (LG-01, UD-02)** A principal's self-check writes a
  `CONSENT_SELF_CHECKED` audit row (initiator PRINCIPAL). It still writes no
  validation row, denial notice or webhook.
- **P10-10 (NT-01)**
  - New default messages for `POLICY_CHANGE_RECONSENT_REQUIRED`,
    `PURGE_SCHEDULED` and `PURGE_EXECUTED`.
  - A type with no template renders as words, never as its enum name.
  - A placeholder the context cannot fill falls back to the type's plain
    wording, or is dropped.
  - `dispatch_notification` takes `context` (or the schema's older
    `payload_data`).
- **P10-11 (CC-01, UD-05)** db/26 replaces the one-active-record-per-fiduciary
  unique index with one active record per principal per policy. The schema
  now matches the service model.
- **UD-05** `principal_login` returns `fiduciary_name`, the fiduciary's live
  `policies` (with ROPA personas), `persona`, `pca_qr_enabled` and
  `sync_token`, which are the keys the rights portal's `saveSession` reads.
- **NT-02** The console's template cards use the notification types the
  services write. db/26 merges the legacy names into them.
  `set_notification_message` refuses unknown types (other than
  `BREACH_NOTIFICATION_*`) and unsupported language codes.
- **NT-03**
  - The console offers English and all 22 Eighth Schedule languages, not only the
    active policy's.
  - Principal-facing defaults ship in Hindi as well as English.
  - Rendering prefers the DPO's text in the principal's language, then the
    built-in text in that language, then English.
- **CC-03** The rights portal pre-ticks no purpose and locks none. A purpose
  the service depends on is labelled as such. Declining it asks for
  confirmation, and exactly what the principal ticked is sent.
- **CU-09** The `CONSENT_GIVEN` audit row lists every purpose a grant or update
  decided (`purpose_ids`, `granted_purpose_ids`, `declined_purpose_ids`), the
  policy version and the superseded record.
- **PL-03** Closing a purpose raises erasure for every principal who ever
  granted it, including those who had already withdrawn.
- **CW-08** A withdrawal, an erasure request or a purpose closure fans out to
  every active processor (app):
  - Each processor gets its own webhook delivery to its own endpoint
    (`processor_webhook_configs`, db/26).
  - Each processor gets its own acknowledgeable PROCESSOR alert.
  - One app's key cannot acknowledge another processor's alert.
  - The console configures the endpoints.
- **UD-03** The rights dashboard filters history by purpose, status and date.
- **UD-04** The rights dashboard downloads the history as CSV or PDF.
- **UD-10** The dashboard shows the grievance reference number and tells the
  principal the reference on submission.
- **GR-03** Grievance notices carry the language the grievance was filed in.
  Delivery uses it before the principal's last consent language.
- **GR-08** `list_pending_grievances`, the fourth reader, returns
  `grievance_id`.
- **SA-13** Erasure re-keys to a random token per erasure, not a keyed hash of
  the identifier. Nobody can recompute it from the original id.
- **P9-05 (residual)** The `consent_records` maintenance opt-in no longer
  permits DELETE, reviving a retired record, changing the cited notice or
  timing, or turning a refused purpose into a granted one.
- **Rule 6(1)(c)** A worker sweep (`jobs.flag_security_anomalies`) raises an
  alert and tells the DPO when failed sign-ins burst within an hour.
- **Rule 6(1)(f)** An API key for an app is issued only once the app records
  its `dpa_reference`.
- **DD-04** The DPO decision register is now `docs/dpo_decision_register.md`
  (DD-01 to DD-04).
- **D10 / D13** are reconciled and tested. D10 is the CHANGELOG test-count and
  CI guard (`test_changelog_test_claims_are_true_and_ci_never_skips`). D13 is
  the README and scripted upgrade lists (`test_readme_upgrade_loop_lists_every_migration`,
  `test_upgrade_script_list_covers_every_migration`).
- Webhook settings: saving with a blank secret keeps the stored secret, as the
  console says, instead of overwriting it with an empty one.
- Tests: 332 passed, 1 skipped (333 collected) against a throwaway Postgres
  with `db/01..26` applied. db/26 re-applies cleanly.

### Fixed (Security workbook v9, p12 remediation round)

Workbook v9 re-verified `2e55f86`. It left four requirements Partial (CU-05,
CW-08, UD-03, LG-05) and raised ten findings (P11-01..P11-10). It also listed
the Rule 6 obligations the review never reached on the Security Coverage
sheet. The findings and the Partial rows are closed in code, each with a
DB-backed regression in `test_p11_remediation.py`. The coverage items the repo
can carry are closed in code and tested in `test_security_coverage.py`. The
rest are now documented controls, each with an owner and a record, under
`docs/security/`.

- **P11-01 (CC-07, CV-01)** The `consent_records` maintenance guard decides
  "granted" with `tsi_point_granted`, which mirrors `_point_granted` exactly:
  Python truthiness of `consent_granted`, else the legacy `status` alias, with
  expiry. The spellings `status: 'true'`, `consent_granted: 'True'` and `1` no
  longer turn a refused purpose into a granted one (db/27).
- **P11-02 (CC-07)** The guard rejects a `data_point_consents` value that is
  not an array. It used to coerce it, which let one UPDATE erase every recorded
  decision.
- **P11-03 / CU-05 (CU-02)** Only one version of a policy is served at a time:
  ACTIVE, in effect, and the newest (`served_policy_version`).
  - Consent can rest only on that version.
  - Activating a version archives the versions it supersedes and closes their
    PENDING re-consent requests.
  - A future-dated version takes over when its effective date arrives. The
    worker's `superseded_policies` sweep does the archiving then.
  - An unversioned consent is stamped with the served version.
- **P11-04 / LG-05** The audit purpose filter compares canonical ids on both
  sides, so whole-account erasures (`ALL`) can be found again.
- **P11-05 / CW-08** A withdrawal, erasure or closure fans out only to
  processors. A processor is an ACTIVE app with an enabled endpoint for the
  event's category and a recorded `dpa_reference`. Other apps no longer receive
  the principal's id, or alerts they could never act on.
- **P11-06 (SA-13, CW-11)** Erasure re-keys the `user_id` in FIDUCIARY and
  PROCESSOR alert payloads as well as in PRINCIPAL ones.
- **P11-07 (CU-01, UD-05)** `get_active_consent` without a `policy_id` still
  returns the newest record at the top level. It now also returns
  `active_records` and `active_record_count`, so the answer is never silently
  partial.
- **P11-08 (PL-01)** Purpose closure looks the lifecycle row up canonically,
  so rows that were never canonicalised still close. A failed time-bound
  closure is now reported as an error in the cycle summary, not as `closed: 0`.
- **P11-09 (NT-02)** `EXPIRY_NOTIFICATION` text is migrated into
  `PURPOSE_CLOSED`, and `PURGE_ONHOLD_NOTIFICATION` into
  `ERASURE_REQUESTED_NOTIFICATION`. Where the live template already has a
  language, the DPO's live text wins. The original rows are archived in
  `notification_message_templates_archive`.
- **P11-10 (UD-01, UD-02)** The rights dashboard's record-detail and withdraw
  modals, and the wallet page, resolve purpose aliases and granted-ness exactly
  as the server does (`pointPurposeId`, `pointGranted`).
- **UD-03** The history status filter's `ACTIVE` option is labelled "In force"
  to match what it returns. A consent record superseded by a later one is
  badged SUPERSEDED, not ACTIVE, so the filter and the badges agree.

### Added (Security Coverage sheet, workbook v9)

- **s.8(6) / Rule 7** Breach handling:
  - `report_breach` honours the affected principal ids and CSV, and the
    category, that the console sends. Both were dropped before. It also
    notifies the principals.
  - New `notify_affected_principals` and `record_board_intimation` (the
    reference is mandatory; a late intimation is recorded as late), with
    console controls for both.
  - The worker's `breach_deadlines` sweep alerts the DPO 12 hours before the
    72-hour Board deadline, and again when it is missed.
- **Rule 6(1)(d)** The worker records a heartbeat each cycle.
  `GET /healthz/worker` returns 503 when the worker is stale or a sweep failed.
  `restore-test.sh` restores a dump into a scratch database and checks that
  the ledger still chains.
- **Rule 6(1)(b)** Row-level security on every tenant table, for any database
  role granted `tsi_tenant_reader`. Such a role sees only the fiduciary set in
  `tsi.fiduciary_id`. The application, as the table owner, is unaffected.
- **Rule 14** `OUTBOUND_ALLOWED_HOSTS` restricts every webhook, gateway,
  verifier and SMTP destination.
- **M-03** Content-Security-Policy, Referrer-Policy and
  Cross-Origin-Opener-Policy headers.
- **M-02** A CI `supply-chain` job: `pip-audit --strict` on the runtime
  requirements, and a failure if any compiled bytecode is committed.
- **Rule 6(1)(a)–(g), S9, S10, M-01, M-04** `docs/security/`: control map,
  key management, backup and continuity, monitoring and review, log
  retention, breach runbook, outbound destinations, pen-test plan.
- DB scripts: `27_p11_remediation.sql`, `28_security_coverage.sql`.

### Fixed (Security workbook v10, p13 remediation round)

Workbook v10 (revision 14) re-verified `ae4bf9e`. It left CC-04 and CW-01
Partial and raised twelve findings (P12-01..P12-12), carried two from the API
inventory (INV-07, INV-08), and kept open items on the Security Coverage sheet
and the DPO register. Each is closed below, with a regression in
`test_p12_remediation.py`.

- **P12-01 / P12-02 (CC-04, CW-01, CW-02, CV-03, UD-04; DD-01)** A consent
  decision may carry only `data_point_id` (or its aliases), `consent_granted`,
  `status`, `purpose_agreed_to` and `timestamp_updated`.
  - `canonical_consent_points` refuses anything else with 400, so
    `consent_expiry` is never the caller's to set.
  - The `record_consent` and `request_reconsent` schemas close their decision
    items (`additionalProperties: false`).
  - `_point_granted` never raises on a stored expiry. A naive value reads as
    UTC, and an unparseable one is ignored. Validation, withdrawal and export
    work again for a principal whose record carries one.
- **P12-03 (CU-03, CC-01)** A version takes effect when it is activated, not
  when it was drafted.
  - Activation sets `effective_date` to the later of now and any future
    `effective_date` the DPO gave `create_policy`, which now honours it.
  - `publish_policy` reports the stored status after superseded versions are
    retired, and `activated_versions` lists only versions still ACTIVE.
- **P12-04 (s.8(6), Rule 7(2))** `record_board_intimation` records
  `board_notified_at` at server time.
  - An earlier intimation time may be asserted as `intimated_at`. It is kept in
    `board_intimated_at_asserted`, must lie between detection and now, and
    decides `late`.
  - `report_breach` refuses a future `detected_at`.
- **Rule 7(1) / 7(2)(b) contents** Breaches record `likely_consequences`,
  `mitigation_measures` and `contact_point`, and the principal notice carries
  them. The detailed report records `circumstances`, `cause_findings` and
  `remedial_measures`. `update_breach_status` accepts all six, and
  `submit_detailed_report` stamps `board_report_submitted_at` once all four
  detailed-report fields are present. The console's breach forms have the new
  fields.
- **P12-05 (Rule 6(1)(b))** Row-level security for `tsi_tenant_reader` no
  longer reads the tenant from `tsi.fiduciary_id`, which the reader could set.
  A reader sees only the tenants mapped to its role in `tsi_reader_tenants`.
  That table is owned by the application and readers can neither read nor
  write it; it is consulted through the SECURITY DEFINER `tsi_reader_may_see`.
- **P12-06 (CC-01)** `consent_policies` is keyed `(fiduciary_id, id,
  version)`. `consent_records` references it through the tenant as well. Any
  `UniqueViolation` reaching the dispatcher is a 409, not a 500.
- **P12-07 (NT-02)** db/27 archives the two legacy templates without merging
  their text into the live types. db/29 removes the languages an earlier run
  filled, wherever the DPO has not since edited them.
  `get_notification_messages` returns the archived text as `archived_legacy`
  beside its live type, and the settings page shows it read-only.
- **P12-08 (M-03, DD-04)** The CSP is `script-src 'self'; script-src-attr
  'none'`.
  - Every page's inline script moved into its own file, and every inline
    handler became an `addEventListener`.
  - Tailwind, qrcodejs and SheetJS are vendored in `web/vendor/`, with sources,
    licences and hashes in its README.
  - No page loads a third-party script, stylesheet or font, so the CDN and
    Google Fonts origins are gone from the policy.
- **P12-09 (Rule 6(1)(d))** `/healthz` and `/healthz/worker` return the
  status only, and exceptions go to the log. A monitor sending `X-Health-Token`
  (`HEALTHZ_TOKEN`) also gets the worker detail.
- **P12-10 (UD-03)** The history purpose filter uses `tsi_point_purpose`,
  which resolves aliases exactly as the gate does.
- **P12-11 (Rule 14)** Outside `TSI_DPDP_CMS_ENV=local`, an empty
  `OUTBOUND_ALLOWED_HOSTS` stops the app from starting. `*` is the explicit
  unrestricted setting. `preflight.sh` checks db/27, db/28 and db/29.
- **P12-12 (Rule 7(2))** `download_breach_report` renders a real PDF
  server-side with every Rule 7 field and both intimation times, served as
  `breach-report.pdf`. The runbook describes it as it now is.
- **INV-07 (SA-09)** `update_purge_status` refuses `COMPLETED` and
  `PURGE_COMPLETED`, in code and in the schema. Completion goes only through
  `confirm_purge_status`, with evidence, and a completed purge cannot be
  completed again. The console's purge form no longer offers it.
- **INV-08 (SA-05)** A key authenticates only while its fiduciary, and its
  app if it has one, is ACTIVE. `delete_app` and `delete_fiduciary` revoke the
  keys and report how many.
- **LG-05** Expression index on `tsi_canonical_purpose(purpose_id)` for the
  audit purpose filter.

### Added (Security Coverage sheet, workbook v10)

- **Rule 6(1)(a)** Operator, fiduciary and app contact details are stored
  encrypted only. The `*_plaintext` columns are no longer written and db/29
  clears them. Operator search matches the decrypted email.
- **Rule 6(1)(c)** Every audit read writes an `AUDIT_LOG_READ` event, and one
  read returns at most 5,000 rows. The access report now includes principal
  sign-ins and ledger reads.
- **Rule 6(1)(d)** `restore-test.sh` recomputes every ledger row hash in the
  restored copy with `verify_chain`. It used to check links only.
- **M-02** `python_port/requirements.lock` is a hash-pinned lockfile
  (pip-compile). The image installs it with `--require-hashes`. CI audits it
  and checks that it covers `requirements.txt`.
- **DD-03 / DD-05** The DPO register records the recurring purpose-validity
  review (DD-05), with its procedure in
  `docs/security/PURPOSE_VALIDITY_REVIEW.md`. Every entry now has recorded,
  last-checked and next-review dates. Each also has a named-holder column that
  the DPO must fill in. DD-04's factual basis now matches the vendored scripts.
- DB script: `29_p12_remediation.sql`.
- Tests: 403 passed, 1 skipped (404 collected) against Postgres 16 with
  `db/01..29` applied. db/27, db/28 and db/29 re-apply cleanly.

### Added (automated pen test, M-01)

- `python_port/pentest/` is an automated, authenticated pen-test suite: 114
  attacks over the real HTTP interface, run against two tenants it
  provisions through the API. It covers authentication and session,
  cross-tenant and role/scope authorisation, injection, business logic, SSRF,
  transport hardening and brute force. It runs locally and in CI
  (`python -m pytest -q pentest`, with the report uploaded as an artifact).
  It can also target staging with `PENTEST_BASE_URL`. See
  `docs/security/PEN_TEST_PLAN.md`; results are in
  `docs/security/PEN_TEST_REPORT.md`.
- **PT-01** A malformed id, an over-long value or a bad date reaching SQL
  (`psycopg.errors.DataError`) is now a 400, not a 500.
- **PT-02** CSV formula injection.
  - `record_consent` refuses a `language_selected` that is not `en` or an
    Eighth Schedule code.
  - The consent-history and ROPA CSVs, and every job export except AUDIT,
    neutralise cells that start with `=`, `+`, `-`, `@`, tab or CR.
  - The AUDIT export stays byte-exact so its row hashes recompute.
- **PT-03** A malformed JSON body (`{not json`) fell through to form
  parsing. Where `python-multipart` is not installed, as in CI and the image,
  that raised and returned a 500. A body is now parsed as a form only when
  its Content-Type says it is one. Invalid JSON, and a form that cannot be
  parsed, are 400.
- Tests: `test_pentest_findings.py`; 427 passed, 1 skipped (428 collected).

### Fixed (Security workbook v11, p14 remediation round)

Workbook v11 (revision 15) re-verified `db2caff`. It left CC-01 Partial on one
new High finding (P13-01) and raised four Low ones (P13-02..P13-05). Each is
closed below, with a regression in `test_p13_remediation.py`.

- **P13-01 (CC-01, SA-03)** Since P12-06 made policy ids per tenant, a global
  ADMIN's `get_policy`, `update_policy`, `publish_policy` and `delete_policy`
  matched every tenant's copy of the id (a `delete_policy` naming tenant B
  archived tenant A's live notice).
  - All four now act on exactly one tenant, `policy_fiduciary(ctx)`: the
    caller's own for a tenant-bound caller, the payload's `fiduciary_id` for a
    global ADMIN, which is refused (400) without one.
  - The DPO console sends the policy's `fiduciary_id` on update and publish.
  - New pen-test case: same-id policies in two tenants, operated on by a
    global ADMIN (`pentest/test_authorization.py`).
- **P13-02 (Rule 7(2))** `record_board_intimation` decides `late` from the
  server-recorded time. The DPO's asserted time is reported beside it as
  `late_as_asserted`, and the breach PDF prints both, the assertion marked
  unverified.
- **P13-03 (Rule 6(1)(b))** `db/30_p13_remediation.sql`: the tenant-reader RLS
  policies consult the security-barrier view `tsi_reader_my_tenants`, which
  returns only the querying role's mappings. The helper
  `tsi_reader_may_see(role, tenant)`, which let a reader test any role's
  mapping, is dropped. Readers still cannot read or write `tsi_reader_tenants`.
- **P13-04 (CC-02)** `language_selected` is an `enum` in the `record_consent`
  and `request_reconsent` schemas (`en` plus the 22 Eighth Schedule codes),
  matching `NOTIFICATION_LANGUAGES`, and documented in `python_port/README.md`.
  Upper-case codes are now refused at the schema.
- **P13-05 (M-02)** `scripts/supply_chain/vendor_audit.py` runs in the
  `supply-chain` CI job. It checks every file in `web/vendor/` against
  `vendor_manifest.json` (SHA-256) and fails on any OSV.dev advisory not
  accepted there with a reason and an unexpired `review_by` date. The two
  SheetJS 0.18.5 parsing advisories are accepted until 15 Jan 2027, and a test
  fails the build if any page calls `XLSX.read`/`XLSX.readFile`.
- **R14 (Security Coverage)** `OUTBOUND_ALLOWED_HOSTS='*'` is refused when
  `TSI_DPDP_CMS_ENV=production`; production must list its destinations.
- **P14-01 (Rule 14)** `TSI_DPDP_CMS_ENV` must be one of `local`, `test`,
  `staging`, `production`, case-folded; any other value refuses to start. A
  free-text `Production` or `prod` no longer bypasses the production-only `'*'`
  refusal.
- DB script: `db/30_p13_remediation.sql` (idempotent).
- Tests: 469 passed, 1 skipped (470 collected) against Postgres 16 with
  `db/01..30` applied; pen test 113 passed, 2 remote-only skipped.

### Upgrade notes

- **New database volume:** Compose applies all `db/*.sql` on first Postgres start — no extra steps.
- **Existing database:** Run `db/13` through `db/30` manually against the live DB (scripts are idempotent). See [README — Database upgrades](README.md#database-upgrades).
- **Environment:** Add `BOOTSTRAP_TOKEN` (min 32 characters) before starting the app or worker. Outside `local`, also set `OUTBOUND_ALLOWED_HOSTS` (or `*`), or the app will not start. `TSI_DPDP_CMS_ENV` must be `local`, `test`, `staging` or `production` (case-insensitive); rename any other value (e.g. `prod`) before upgrading. With `production`, `*` is refused: list the hosts. Optionally set `HEALTHZ_TOKEN` for health detail.
- **Global ADMIN policy calls:** send `fiduciary_id` with `get_policy`, `update_policy`, `publish_policy` and `delete_policy`.
- **Tenant readers:** after db/29, a role in `tsi_tenant_reader` sees nothing until a row in `tsi_reader_tenants` maps it to a tenant; `tsi.fiduciary_id` is no longer read.
- **Rights portal:** Outside `local`, set each fiduciary's OTP mode to `EMAIL_OTP`/`MOBILE_OTP` with an `OTP` webhook, or set `ALLOW_DUMMY_OTP=true` for a demo — `DUMMY_OTP` logins are otherwise refused.
- **Roles:** Built-in DPO/OPERATOR/AUDITOR permissions are extended by `17`; review custom roles, which now need explicit `<resource>:<action>` grants for every admin function they call.
- **Audit ledger:** After `19`, `audit_logs` rejects UPDATE, DELETE and TRUNCATE for every role. Any maintenance job that edits or prunes audit rows must be retired first.
- **Process:** Run the background worker in production (`python -m dpdpcms_py.worker` or Compose `python_worker`).

### Not in repository

- MeitY BRD traceability workbook and internal findings documents are local-only (listed in `.gitignore`).
