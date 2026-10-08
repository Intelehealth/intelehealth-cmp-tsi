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

- Unit tests under `python_port/tests/` (205 tests: P1/P2 helpers, SSRF, TOTP, roles, retention, a regression test per open defect in `test_defect_fixes.py`, BRD traceability rules in `test_brd_traceability.py`, the workbook v4 defects in `test_review_v4_fixes.py`, the workbook v5 defects in `test_review_v5_fixes.py`, the security-gap fixes in `test_security_gaps.py`, and the bugs found re-verifying the BRD sheet in `test_brd_v5_bugs.py`).
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

### Upgrade notes

- **New database volume:** Compose applies all `db/*.sql` on first Postgres start — no extra steps.
- **Existing database:** Run `db/13` through `db/21` manually against the live DB (scripts are idempotent). See [README — Database upgrades](README.md#database-upgrades).
- **Environment:** Add `BOOTSTRAP_TOKEN` (min 32 characters) before starting the app or worker.
- **Rights portal:** Outside `local`, set each fiduciary's OTP mode to `EMAIL_OTP`/`MOBILE_OTP` with an `OTP` webhook, or set `ALLOW_DUMMY_OTP=true` for a demo — `DUMMY_OTP` logins are otherwise refused.
- **Roles:** Built-in DPO/OPERATOR/AUDITOR permissions are extended by `17`; review custom roles, which now need explicit `<resource>:<action>` grants for every admin function they call.
- **Audit ledger:** After `19`, `audit_logs` rejects UPDATE, DELETE and TRUNCATE for every role. Any maintenance job that edits or prunes audit rows must be retired first.
- **Process:** Run the background worker in production (`python -m dpdpcms_py.worker` or Compose `python_worker`).

### Not in repository

- MeitY BRD traceability workbook and internal findings documents are local-only (listed in `.gitignore`).
