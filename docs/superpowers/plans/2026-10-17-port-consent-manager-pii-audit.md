# Port Consent-Manager PII & Audit Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Encrypt every Data Principal identifier, guardian evidence and consent IP in p5, partition and archive `audit_logs`, add `grievances.channel`, and ship `reveal_user_id`, `get_parental_verification` and `get_consent_audit_trail` with their DPO UI.

**Architecture:** New SQL migrations `31`–`36` in `db/`. A new `dpdpcms_py/pii.py` owns every principal-ID crypto/masking primitive; services switch their SQL to `_enc`/`_hmac` columns through it. A new `PiiService` (`services/pii.py`) serves reveals. Audit archiving is a worker sweep in `jobs.py`. UI changes are CSP-clean edits to existing `web/console/dpo/*.js`.

**Tech Stack:** Python 3.12, FastAPI, psycopg 3, PostgreSQL 15/16 + pgcrypto, jsonschema, pytest, ruff; vanilla JS + vendored Tailwind.

**Spec:** `docs/superpowers/specs/2026-10-17-port-consent-manager-pii-audit-design.md`. Behaviour reference (read-only): `C:\Users\Satya\Documents\Downloads_dump\Consent-Manager` — `src/org/tsicoop/dpdpcms/service/v1/Pii.java`, `framework/PiiMasking.java`, `service/v1/Consent.java` (`get_consent_audit_trail`, `get_parental_verification`), `job/JobManager.java` (`checkAndArchiveAuditPartitions`), `db/13`–`19`, `web/console/dpo/principals.html`, commits `2f22587 a182dbc f0d65af da3146b`.

## Global Constraints

- Edit only inside `C:\Users\Satya\Documents\Downloads_dump\intelehealth-cmp-tsi-p5`. Branch `feat/port-cm-pii-audit`.
- New migrations are `db/31_*.sql` onward, one concern per file, idempotent where Postgres allows, applied in filename order by both `docker-entrypoint-initdb.d` and CI (`for f in db/*.sql; psql -v ON_ERROR_STOP=1`). CI does **not** run `03z_enc_key.sh`, so `app.enc_key` may be unset on an empty DB.
- Backfill rule: backfill when `current_setting('app.enc_key', true)` is non-empty; if rows exist and the key is unset, `RAISE EXCEPTION` before dropping anything.
- Principal-ID HMAC = `encode(hmac(trim(v), key, 'sha256'), 'hex')` — **trim only, no lower()**. Python and SQL must agree byte for byte.
- Encryption = `encode(pgp_sym_encrypt(v, key), 'base64')`; decryption = `pgp_sym_decrypt(decode(c, 'base64'), key)`.
- `UPDATE consent_records` only inside a transaction that called `db.allow_consent_maintenance(cur)` (SQL: `SELECT set_config('tsi.consent_maintenance','on',true)`).
- `audit_logs.user_id` stays `security.pseudonym(raw)`; never re-key it.
- Reveal: roles DPO (own fiduciary) and ADMIN (any fiduciary) only; permission `pii:reveal`; never reachable by API key or principal token; 20 reveals / operator / rolling 60 s; audit row committed before plaintext is returned.
- Console (operator) responses mask principal IDs by default; plaintext only for: API-key callers on their own fiduciary's principals, PURGE-scope processors on purge-request reads and `confirm_purge_status`, processor webhooks/alerts, a principal on `export_consent_history` for themselves.
- Audit archive window env `AUDIT_LIVE_YEARS`, default `3` (current + 2 prior).
- Grievance channels: `PORTAL` (default), `EMAIL`, `PHONE`, `LETTER`, `IN_PERSON`, `OTHER`.
- UI: no inline `<script>`, no `on*=` attributes; wire with `data-action` + the page's `clickHandlers` map; no CDN URLs.
- Gates per task: `ruff check python_port`, `ruff format --check python_port`, `cd python_port && python -m pytest -q tests` (integration tests run when Postgres env is set).

## Review Focus

1. A principal ID with leading/trailing spaces (`" a@b.com "`) recorded then looked up without spaces must resolve to the same principal — test in Task 3 (`test_pid_hmac_trims_but_keeps_case`) and Task 5 integration.
2. A principal ID differing only in case (`ABC123` vs `abc123`) must stay two principals — Task 3 unit + Task 5 integration.
3. Erasure after encryption: an erased principal's consent rows must hold the encrypted `erased:<token>` placeholder and `0.0.0.0` IP, and a second erasure must not fail on the append-only trigger — Task 6 integration.
4. Inserting an audit row dated in a year with no partition (e.g. clock at Dec 31 → Jan 1) must not fail — Task 2 `test_default_partition_catches_unplanned_year`.
5. An OPERATOR or AUDITOR calling `reveal_user_id`, or any API-key / principal-token caller, gets 403 and no audit row; the 21st reveal inside 60 s gets 429 — Task 9 tests.

---

### Task 1: Grievance channel

**Files:**
- Create: `db/31_grievance_channel.sql`
- Modify: `python_port/dpdpcms_py/services/compliance.py` (`GrievanceService.submit_grievance` ~L723, `get_grievance` ~L856, `list_grievances` ~L879)
- Modify: `web/WEB-INF/validator/submit_grievance.jschema`
- Modify: `web/console/dpo/grievances.html`, `web/console/dpo/grievances.js`
- Test: `python_port/tests/test_pii_port.py` (new file, shared by later tasks)

**Interfaces:**
- Produces: `GRIEVANCE_CHANNELS = ("PORTAL","EMAIL","PHONE","LETTER","IN_PERSON","OTHER")` in `services/compliance.py`; `channel` key on every grievance returned by get/list.

- [ ] **Step 1: Failing tests** in `tests/test_pii_port.py`:
  - `test_grievance_channel_defaults_to_portal_for_principal_and_api_callers` — a principal-token or API-key submit carrying `channel="EMAIL"` is stored as `PORTAL`.
  - `test_dpo_can_log_offline_grievance_with_channel` — operator submit with `channel="PHONE"` stores `PHONE`; `channel="FAX"` → `ApiError` 400.
  - Integration (uses `tx`): `test_grievance_channel_column_defaults_portal` — insert without channel, read back `PORTAL`.
- [ ] **Step 2:** `cd python_port && python -m pytest -q tests/test_pii_port.py` → FAIL.
- [ ] **Step 3:** Migration: `ALTER TABLE grievances ADD COLUMN IF NOT EXISTS channel VARCHAR(20) NOT NULL DEFAULT 'PORTAL'` + `CHECK (channel IN (...))` constraint named `grievances_channel_check` (drop-if-exists then add) + column comment. Service: operator callers (`ctx.operator_id` set) may pass `channel`; everyone else forced to `PORTAL`. Validator: optional `channel` enum. Include `channel` in get/list SELECTs.
- [ ] **Step 4: UI.** Port Consent-Manager's DPO "Log grievance" modal (see its `web/console/dpo/grievances.html`) into p5's `grievances.html` markup + `grievances.js` handler: fields principal ID, category, description, channel select (non-PORTAL options). Show a Channel column/badge in the list and detail.
- [ ] **Step 5:** tests PASS, ruff clean.
- [ ] **Step 6: Commit** `feat: record how a grievance reached the fiduciary (channel)`.

### Task 2: Partition audit_logs by year + archive registry + archive sweep

**Files:**
- Create: `db/32_partition_audit_logs.sql`, `db/33_audit_archive_registry.sql`
- Modify: `python_port/dpdpcms_py/jobs.py` (new sweep), `python_port/dpdpcms_py/worker.py` (register + `list_sweeps`), `python_port/dpdpcms_py/config.py` (`audit_live_years`), `python_port/dpdpcms_py/audit.py` (`verify_chain`, `list_logs`, `get_log` read across archives), `.env.example` (document `AUDIT_LIVE_YEARS`)
- Test: `python_port/tests/test_pii_port.py`

**Interfaces:**
- Produces: `jobs.archive_audit_partitions(now: datetime | None = None) -> dict[str, int]` returning `{"created": n, "archived": n}`; `audit.ledger_source() -> str` — a SQL `FROM` fragment (`audit_logs` alone, or a parenthesised `UNION ALL` of `audit_logs` and every `audit_log_archive_registry.partition_name`, aliased `audit_logs`), validated table names only (`^audit_logs_y\d{4}_archive$`).
- Consumes: `settings.audit_live_years: int` (env `AUDIT_LIVE_YEARS`, default 3, min 1).

- [ ] **Step 1: Failing tests:**
  - Integration `test_audit_logs_is_partitioned_with_default` — `pg_partitioned_table` has `audit_logs`; a DEFAULT partition exists.
  - Integration `test_default_partition_catches_unplanned_year` — `log_event` with a patched clock in year 2099 succeeds.
  - Integration `test_append_only_triggers_apply_to_partitions` — `UPDATE audit_logs SET audit_action='X'` raises.
  - Integration `test_archive_sweep_detaches_old_years_and_chain_still_verifies` — seed rows in `now.year-4`, run `archive_audit_partitions(now)`, assert table `audit_logs_y<year>_archive` exists, registry row with `row_count`, `audit_logs` no longer contains those rows, and `audit.verify_chain(...)` over the full window reports intact.
  - Unit `test_ledger_source_rejects_unexpected_registry_names` — a registry name `x; DROP` is skipped.
- [ ] **Step 2:** run → FAIL.
- [ ] **Step 3: Migration 32.** Pre-production reset per spec: rename the current `audit_logs` to `audit_logs_legacy_pre32` (rename its indexes with `_legacy` suffix, drop its triggers), then `CREATE TABLE audit_logs (...) PARTITION BY RANGE (timestamp)` with **the exact current column list** (derive from `db/01_init.sql` plus every later `ALTER TABLE audit_logs` in `db/02`–`db/30`; `grep -n "audit_logs" db/*.sql`), PK `(id, timestamp)`. Create yearly partitions for `2025`..`EXTRACT(year FROM now())+1` via a `DO` block, plus `audit_logs_default PARTITION OF audit_logs DEFAULT`. Recreate every index and trigger that `db/19`, `db/24` and later files define on `audit_logs` (row triggers on the parent; TRUNCATE trigger on the parent). Do **not** copy legacy rows (chain restarts from genesis — spec decision); header comment explains the legacy table may be dropped by an operator. Recreate any FK/view that pointed at the old table (check `audit_chain_verifications`, functions in `db/24`).
- [ ] **Step 4: Migration 33.** `audit_log_archive_registry(id uuid pk default uuid_generate_v4(), partition_name varchar(100) unique not null, period_start timestamp not null, period_end timestamp not null, archived_at timestamptz default now(), row_count integer)`.
- [ ] **Step 5: Sweep.** `archive_audit_partitions`: ensure partitions exist for `now.year` and `now.year+1` (moving any rows out of DEFAULT is unnecessary if default is empty; if DEFAULT holds rows for that year, skip creation and log); for each yearly partition with year `< now.year - (audit_live_years - 1)`: `ALTER TABLE audit_logs DETACH PARTITION ...`, `ALTER TABLE ... RENAME TO audit_logs_y<YYYY>_archive`, re-add the append-only triggers to the detached table, insert registry row with `row_count`. Each partition in its own transaction. Register in `worker.run_cycle` and `list_sweeps`.
- [ ] **Step 6: Readers.** `verify_chain`, `list_logs`, `get_log` and any certificate trail query in `services/governance.py` select `FROM {audit.ledger_source()}`; `log_event`'s "previous row" lookup stays on live `audit_logs`.
- [ ] **Step 7:** tests PASS; ruff clean.
- [ ] **Step 8: Commit** `feat: partition audit_logs by year and archive old years without deleting`.

### Task 3: Principal-ID crypto and masking primitives

**Files:**
- Create: `python_port/dpdpcms_py/pii.py`
- Test: `python_port/tests/test_pii_port.py`

**Interfaces:**
- Produces (all in `dpdpcms_py/pii.py`):
  - `normalize(value: str | None) -> str | None` — `value.strip()`, `None` passthrough.
  - `HMAC_SQL = "encode(hmac(trim(%s), %s, 'sha256'), 'hex')"` and `ENC_SQL = db.enc_expr()`.
  - `hmac_params(value) -> tuple[str | None, str]` and `enc_params(value) -> tuple[str | None, str]` — both normalise first, append `settings.db_encryption_key`.
  - `hmac_hex(value: str) -> str` — Python HMAC-SHA256 hex of `normalize(value)` keyed by `settings.db_encryption_key` (used where SQL is not available, e.g. job payloads).
  - `dec_sql(column: str) -> str` — `db.decrypt_col(column)`; caller binds `db.bind_key()`.
  - `mask(value: str | None) -> str | None` — port of `PiiMasking.mask/maskEmail/maskPhone`: email `a***@d***.com` (first char of local part, first char of domain label, keep TLD), phone keeps `+` and up to 2 digits then `*` with last 2 digits, anything else first 2 chars + `***`; `None`/`""` passthrough; values starting `erased:` returned as `erased`.
  - `principal_view(ctx: RequestContext, raw: str | None) -> str | None` — returns `raw` for API-key callers, principal tokens and processors (`ctx.operator_id is None`), else `mask(raw)`.
- [ ] **Step 1: Failing tests:** `test_pid_hmac_trims_but_keeps_case` (`hmac_hex(" ABC ") == hmac_hex("ABC") != hmac_hex("abc")`); `test_mask_email_phone_other` with exact strings: `mask("satish@test.com") == "s***@t***.com"`, `mask("+919876543210") == "+91********10"`, `mask("AB1234") == "AB***"`, `mask("erased:9f") == "erased"`; `test_principal_view_masks_only_for_operators`. Integration: `test_python_and_sql_hmac_agree` — `SELECT encode(hmac(trim(%s), %s,'sha256'),'hex')` equals `hmac_hex` for `" x@y.z "`.
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** PASS + ruff.
- [ ] **Step 5: Commit** `feat: principal-ID HMAC, encryption and masking helpers`.

### Task 4: Migration — encrypt principal identifiers, drop plaintext

**Files:**
- Create: `db/34_principal_pii_encryption.sql`
- Test: `python_port/tests/test_pii_port.py`

**Interfaces:**
- Produces columns `<col>_enc TEXT NOT NULL`, `<col>_hmac TEXT NOT NULL` (nullable pair where the source column was nullable) replacing, for each table: `consent_records.user_id`; `data_principal.user_id`, `.guardian_id`; `grievances.user_id`; `purge_requests.user_id`; `consent_validations.user_id`; `breach_affected_principals.user_id`; `parental_verification_logs.child_principal_id`, `.guardian_principal_id`; `notifications.recipient_id`; `data_correction_requests.user_id`; `reconsent_requests.user_id`; `notification_deliveries.recipient_id`; `nominations` principal + nominee identifier columns. Before writing, run `grep -niE "user_id|principal_id|recipient_id|guardian_id|nominee" db/*.sql` and add any other column holding a raw principal identifier (record the inventory in the file header). Excluded: `audit_logs.user_id` (pseudonym), `principal_otps.subject_hash` (already HMAC).
- [ ] **Step 1: Failing integration tests:** `test_no_plaintext_principal_columns_remain` (query `information_schema.columns` for the dropped names on those tables → 0 rows); `test_hmac_keys_replace_plaintext_keys` (`data_principal` PK is `(user_id_hmac, fiduciary_id)`; `breach_affected_principals` PK `(breach_id, user_id_hmac)`; partial unique index on active consent uses `user_id_hmac`).
- [ ] **Step 2:** FAIL.
- [ ] **Step 3: Write migration.** One transaction. `DO` guard: if any affected table has rows and `coalesce(current_setting('app.enc_key', true),'') = ''` → `RAISE EXCEPTION`. Per column: add `_enc`/`_hmac`, backfill (trim-only HMAC), mirror every index/unique/PK that used the plaintext column onto `_hmac`, then drop plaintext. `consent_records` backfill under `set_config('tsi.consent_maintenance','on',true)`. Also recreate any trigger function, view or SQL function in `db/23`–`db/30` that references a dropped column (grep them: e.g. delivery-floor triggers, purpose canonicalisation) so it compiles against `_hmac`.
- [ ] **Step 4:** Apply all migrations to a fresh DB (see "Local DB" below) → no errors; tests in this task PASS. (Service code is broken until Tasks 5–8; do not run the full suite yet.)
- [ ] **Step 5: Commit** `feat(db): store principal identifiers encrypted with HMAC lookup keys`.

### Task 5: Cut over consent, principal and wallet services

**Files:**
- Modify: `python_port/dpdpcms_py/services/consent.py`, `python_port/dpdpcms_py/services/base.py` (principal scoping helpers `bind_principal_field`, `ensure_principal_owns`, `principal_list_filter`), `python_port/dpdpcms_py/main.py` (any principal lookup during auth), `python_port/dpdpcms_py/principal_otp.py` if it reads `data_principal`
- Test: `python_port/tests/test_pii_port.py` + existing suites

**Interfaces:**
- Consumes: Task 3 `pii.*`. Rule for every query: equality/filter/join on a principal ID → `<col>_hmac = {pii.HMAC_SQL}` with `*pii.hmac_params(v)`; insert → both `{pii.ENC_SQL}` and `{pii.HMAC_SQL}`; reading the identifier back → `{pii.dec_sql('<col>_enc')} AS <col>` with `*db.bind_key()`, then `pii.principal_view(ctx, ...)` before returning; `ON CONFLICT (user_id, fiduciary_id)` → `(user_id_hmac, fiduciary_id)`. Webhook/alert payloads keep the raw ID the caller supplied.
- [ ] **Step 1: Failing integration tests:** `test_record_list_withdraw_consent_round_trip_encrypted` (record via `ConsentService.record_consent` with an API-key ctx, `get_active_consent` returns the plaintext ID to that API-key ctx, `list_consents` to an operator ctx returns `mask(id)`, raw row has no plaintext); `test_principal_ids_with_spaces_resolve_and_case_stays_distinct`.
- [ ] **Step 2:** FAIL. **Step 3:** cut over every query in the listed files (`grep -n "user_id\|guardian_id\|child_principal_id\|guardian_principal_id\|recipient_id" <file>` and fix each hit). **Step 4:** `python -m pytest -q tests` — this task's tests and all consent-related existing tests PASS.
- [ ] **Step 5: Commit** `refactor: consent and principal services read and write encrypted principal IDs`.

### Task 6: Cut over compliance (purge, grievance, breach)

**Files:**
- Modify: `python_port/dpdpcms_py/services/compliance.py`
- Test: `python_port/tests/test_pii_port.py` + `tests/test_integration_db.py` erasure tests

**Interfaces:** same rules as Task 5. Erasure writes `erased:<token>` through `ENC_SQL`/`HMAC_SQL`; IP scrub writes `ip_address_enc` (done in Task 8 — here keep the existing `ip_address` statement until Task 8 drops the column; Task 8 updates it). PURGE-scope processors (`ctx.app_id` set, `ctx.operator_id is None`) get plaintext from `list_purge_requests`, `get_purge_request`, `confirm_purge_status`.
- [ ] **Step 1: Failing tests:** `test_erasure_writes_encrypted_placeholder_and_is_repeatable`; `test_processor_sees_plaintext_purge_user_id_operator_sees_mask`; `test_grievance_search_by_principal_is_exact_match`.
- [ ] **Step 2–4:** FAIL → cut over → full suite for compliance tests PASS (existing `test_erasure_*` tests updated only where they asserted plaintext columns).
- [ ] **Step 5: Commit** `refactor: compliance services use encrypted principal IDs`.

### Task 7: Cut over remaining services, jobs and delivery

**Files:**
- Modify: `services/governance.py`, `services/catalog.py`, `services/admin.py`, `services/alerts.py`, `services/lifecycle.py`, `services/rights.py`, `services/retention.py`, `jobs.py`, `delivery.py`, `webhooks.py`, `security.py` (if it reads principal tables)
- Test: `python_port/tests/test_pii_port.py` + full suite

**Interfaces:** same rules. Export jobs (`jobs._write_export`): operator-requested exports write `pii.mask(...)`; `export_consent_history` for a principal returns their own plaintext ID. `jobs.input_payload` must carry `pii.hmac_hex(id)` or record IDs, never a raw principal ID. Notification delivery decrypts `recipient_id_enc` at send time.
- [ ] **Step 1: Failing tests:** `test_export_job_writes_masked_principal_ids`; `test_job_input_payload_has_no_raw_principal_id`; `test_notification_delivery_decrypts_recipient`.
- [ ] **Step 2–4:** FAIL → cut over → **full** `python -m pytest -q tests` and `python -m pytest -q pentest` PASS (pentest needs the app running; if it cannot run locally, record that and rely on CI).
- [ ] **Step 5:** `grep -rnE "\b(user_id|guardian_id|recipient_id|child_principal_id|guardian_principal_id)\b" python_port/dpdpcms_py` — every remaining hit is an `audit_logs.user_id`, a payload key, a `_enc/_hmac` alias, or a non-principal column; note any intentional survivors in the commit message.
- [ ] **Step 6: Commit** `refactor: remaining services, exports and delivery use encrypted principal IDs`.

### Task 8: Encrypt guardian evidence and consent IP; pseudonymise audit details

**Files:**
- Create: `db/35_evidence_ip_encryption.sql`
- Modify: `services/consent.py` (parental verification insert ~L540, consent insert ~L403/L1179), `services/compliance.py` (IP scrub ~L220), `audit.py` (`log_event`)
- Test: `python_port/tests/test_pii_port.py`

**Interfaces:**
- Produces: `parental_verification_logs.verification_ref_id_enc`, `.proof_metadata_enc` (text, JSON string encrypted); `consent_records.ip_address_enc NOT NULL`; plaintext columns dropped (same key guard as Task 4; `consent_records` under maintenance setting).
- `audit.log_event`: before hashing, `details` dict values under keys in `PRINCIPAL_DETAIL_KEYS = {"user_id","principal_id","child_principal_id","guardian_principal_id","guardian_id","recipient_id","nominee_id"}` are replaced by `security.pseudonym(value)` (recursively into nested dicts/lists); string `details` are left as-is. `source_ip`, when given, is stored as ciphertext obtained via `SELECT encode(pgp_sym_encrypt(%s,%s),'base64')` before the row hash is computed (hash covers the stored ciphertext).
- [ ] **Step 1: Failing tests:** `test_consent_ip_and_guardian_evidence_stored_encrypted`; `test_audit_details_pseudonymise_principal_keys` (nested dict); `test_audit_source_ip_encrypted_and_chain_verifies`; `test_erasure_scrubs_encrypted_ip`.
- [ ] **Step 2–4:** FAIL → implement → full suite PASS.
- [ ] **Step 5: Commit** `feat: encrypt guardian evidence and consent IP; pseudonymise principal IDs in audit details`.

### Task 9: `reveal_user_id`

**Files:**
- Create: `python_port/dpdpcms_py/services/pii.py` (`PiiService`), `web/WEB-INF/validator/reveal_user_id.jschema` (port Consent-Manager's), `db/36_pii_reveal_permission.sql`
- Modify: `services/__init__.py` (`"pii": PiiService`), `services/roles.py` (`SERVICE_RESOURCES["pii"]="pii"`, `FUNC_PERMISSIONS[("pii","reveal_user_id")]="pii:reveal"`), `main.py` only if admin-category routing needs the new service listed
- Test: `python_port/tests/test_pii_port.py`

**Interfaces:**
- Produces: `POST /api/v1/admin/pii` `_func=reveal_user_id`, payload `{source, fiduciary_id, id?, user_ref?}`; `source ∈ {consent_record, grievance, purge_request, data_principal, parental_verification}`; `data_principal` uses `user_ref` = the `user_id_hmac`; response `{source, id, fields: {user_id?, ip_address?, guardian_id?, verification_ref_id?, proof_metadata?}}`. Errors: 400 bad source/missing id, 403 role or tenant, 404 not found, 429 rate.
- Migration 36: add `"pii:reveal"` to the built-in DPO role's permissions (additive, like `db/17`).
- Behaviour: require `ctx.operator_id` and `ctx.actor_role.upper() in {"DPO","ADMIN"}` **and** `pii:reveal`; DPO must have `fiduciary_id == ctx.fiduciary_id`; rate limit = count of `audit_logs` rows with `audit_action='PII_REVEALED'` and `initiator=ctx.operator_id` in the last 60 s (≥20 → 429); call `log_event(subject_raw, fid, "DPO_CONSOLE", None, "PII_REVEALED", {"source":…, "record_id":…, "fields":[…]}, initiator=ctx.operator_id)` and only then return decrypted values. Whitelisted table/column map exactly as `Pii.java` `SOURCE_MAP`; never interpolate client input into SQL.
- [ ] **Step 1: Failing tests:** `test_dpo_reveals_own_tenant_and_audit_row_precedes_response`; `test_admin_reveals_any_tenant`; `test_operator_auditor_api_key_principal_get_403_and_no_audit_row`; `test_dpo_other_tenant_403`; `test_21st_reveal_in_a_minute_is_429`; `test_unknown_source_400`.
- [ ] **Step 2–4:** FAIL → implement → PASS + ruff.
- [ ] **Step 5: Commit** `feat: audited, rate-limited reveal of principal identifiers for DPO and admin`.

### Task 10: `get_parental_verification` and `get_consent_audit_trail`

**Files:**
- Modify: `services/consent.py` (`ConsentService`), `services/roles.py` if a read override is needed (both are `get_` → `consent:read`)
- Create: `web/WEB-INF/validator/get_parental_verification.jschema`, `web/WEB-INF/validator/get_consent_audit_trail.jschema` (port from Consent-Manager)
- Test: `python_port/tests/test_pii_port.py`

**Interfaces:**
- `get_parental_verification(ctx)` payload `{consent_record_id, fiduciary_id}` → `{verification_log_id, provider_name, verification_status, verified_at, guardian_id: mask(...), verification_ref_id: mask(...), has_proof_metadata: bool, verification_detail}`; operator-only (reject API key and principal token); 404 when the record is not a minor's.
- `get_consent_audit_trail(ctx)` payload `{consent_record_id, fiduciary_id}` → `{consent_record_id, purposes: [{purpose_id, purpose_name, fields: [str], events: [{timestamp, audit_action, service_type, service_id, current_log_hash, prev_log_hash, context}]}]}`. Events = rows from `audit.ledger_source()` where `user_id = pseudonym(decrypted principal)` and `fiduciary_id` matches and the event references this record or its `supersedes_record_id` chain; grouped by `purpose_id` (`NULL` → `"ALL"`), `fields` = data-point names covered by that purpose in the consent's policy. Match Consent-Manager's grouping (commit `f0d65af`). Operator-only.
- [ ] **Step 1: Failing tests:** `test_parental_verification_is_masked_and_minor_only`; `test_consent_audit_trail_groups_by_purpose_and_carries_service_id`; `test_audit_trail_rejects_api_key_and_principal`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5: Commit** `feat: per-consent audit trail and guardian verification details for DPOs`.

### Task 11: DPO console UI

**Files:**
- Modify: `web/console/dpo/principals.html`, `principals.js`, `compliance.html`, `compliance.js`, `grievances.html`, `grievances.js`
- Test: `python_port/tests/test_pii_port.py` (static checks) + manual load in browser if the stack runs

**Interfaces:** consumes Task 9/10 endpoints and `/api/v1/admin/app` `get_app`.
- [ ] **Step 1: Failing static test** `test_dpo_pages_have_no_inline_handlers_and_call_new_funcs`: the three `.html` files contain no `<script>` without `src` and no ` on[a-z]+=`; `principals.js` references `get_consent_audit_trail`, `get_parental_verification`, `reveal_user_id`, `withdraw_consent`; `compliance.js` and `grievances.js` reference `reveal_user_id`.
- [ ] **Step 2:** FAIL.
- [ ] **Step 3:** Port from Consent-Manager `web/console/dpo/principals.html` (inline script) into p5's `principals.js` structure: audit trail grouped by purpose with fields and "Submitted via" (resolve `service_type=='APP'` via cached `get_app`), guardian verification panel for minors, per-purpose revoke (`withdraw_consent` with a single purpose), Reveal button labelled "Reveal — this action is logged" shown only when the stored role (`localStorage` role key p5 already uses) is DPO or ADMIN; the same Reveal control on compliance purge rows and grievance rows. All handlers via `data-action`.
- [ ] **Step 4:** static test PASS; if Docker stack runs, load each page and confirm no CSP console errors.
- [ ] **Step 5: Commit** `feat(ui): DPO audit trail, guardian details, per-purpose revoke and logged reveal`.

### Task 12: Docs and final verification

**Files:** `CHANGELOG.md`, `README.md` (env table: `AUDIT_LIVE_YEARS`), `python_port/README.md` (worker sweep list), `docs/security/KEY_MANAGEMENT.md` (principal IDs now depend on `DB_ENCRYPTION_KEY`), `docs/security/LOG_RETENTION.md` (archive behaviour).
- [ ] **Step 1:** Write entries (one "P15" section in CHANGELOG listing migrations 31–36 and new endpoints).
- [ ] **Step 2: Fresh-DB verification:** apply `db/*.sql` to an empty DB with and without `app.enc_key` → both succeed (empty tables); then with rows and no key → migration 34 aborts (manual check, documented in the task report).
- [ ] **Step 3:** `ruff check python_port && ruff format --check python_port && cd python_port && python -m pytest -q tests` → all PASS; report counts.
- [ ] **Step 4: Commit** `docs: changelog and runbooks for principal encryption and audit archiving`.

## Local DB (for integration tests)

```bash
docker run -d --name p5-testdb -e POSTGRES_DB=ci -e POSTGRES_USER=ci -e POSTGRES_PASSWORD=ci-password-0123456789abcdef -p 127.0.0.1:5434:5432 postgres:16
for f in db/*.sql; do docker exec -i p5-testdb psql -q -v ON_ERROR_STOP=1 -U ci -d ci < "$f"; done
export POSTGRES_HOST=postgresql://localhost:5434 POSTGRES_DB=ci POSTGRES_USER=ci POSTGRES_PASSWD=ci-password-0123456789abcdef \
  JWT_SECRET=ci-jwt-0123456789abcdef0123456789abcdef DB_ENCRYPTION_KEY=ci-enc-0123456789abcdef0123456789abcdef \
  TSI_LOOKUP_SALT=ci-salt-0123456789abcdef0123456789abcdef BOOTSTRAP_TOKEN=ci-boot-0123456789abcdef0123456789abcdef TSI_DPDP_CMS_ENV=local
```
Reset between migration changes: `docker rm -f p5-testdb` and re-run.
