# Port Consent-Manager PII protection and DPO evidence features to p5

Date: 2026-10-17
Status: draft for review

## Intent

intelehealth-cmp-tsi-p5 (this repo, Python/FastAPI) was ported from a snapshot of
Consent-Manager (Java, `C:\Users\Satya\Documents\Downloads_dump\Consent-Manager`).
Consent-Manager has since shipped features that p5 never received. The most
important gap is that p5 stores Data Principal identifiers, guardian verification
evidence and consent IP addresses in plaintext, while Consent-Manager encrypts
them. The rest are DPO evidence tools and operational fixes.

The two repos are separate products and will stay separate. Nothing here needs
to keep p5's schema or API compatible with Consent-Manager. Consent-Manager is a
reference for behaviour, not a contract.

## Goals

Port these seven items into p5, rewritten in p5's own idiom (service modules in
`python_port/dpdpcms_py/services/`, `db.py` helpers, JSON Schema validators,
the worker, pytest):

1. **Principal PII encryption.** Every column holding a Data Principal's raw
   identifier is replaced by `<col>_enc` (pgcrypto, base64) and `<col>_hmac`
   (keyed HMAC-SHA256 of `trim(value)`, case preserved; see "Case
   sensitivity"). Plaintext columns are dropped.
2. **Guardian evidence encryption.** `parental_verification_logs.verification_ref_id`
   and `proof_metadata` become encrypted-only.
3. **Consent IP encryption.** `consent_records.ip_address` becomes
   `ip_address_enc` only.
4. **Audit-log partitioning and archiving.** `audit_logs` becomes range-partitioned
   by year; a worker sweep detaches partitions older than the retention window,
   renames them `audit_logs_y<YYYY>_archive`, and records them in
   `audit_log_archive_registry`. Nothing is deleted.
5. **Grievance channel.** `grievances.channel`
   (`PORTAL`, `EMAIL`, `PHONE`, `LETTER`, `IN_PERSON`, `OTHER`; default `PORTAL`),
   plus the DPO-side "Log grievance" modal for grievances received offline.
6. **DPO evidence endpoints.**
   - `reveal_user_id` (new `pii` resource): decrypts one record's identifiers for
     an operator, audit-logs the reveal synchronously *before* returning plaintext,
     rate-limited per operator. Sources: `consent_record` (user ID + IP),
     `grievance`, `purge_request`, `data_principal`, `parental_verification`
     (guardian ID, ref ID, proof metadata). Never callable with an API key.
   - `get_parental_verification`: masked guardian verification details for a
     minor's consent record.
   - `get_consent_audit_trail`: for one consent record, the matching
     `audit_logs` entries, grouped by purpose with covered field names, including
     `service_type` and `service_id` so the UI can show which app submitted it.
7. **UI.** On the DPO principals page: audit trail grouped by purpose with a
   "Submitted via" line, guardian verification panel, per-purpose revoke, and a
   "Reveal - this action is logged" control. Reveal controls also on the
   compliance (purge requests) and grievances pages. All new UI follows p5's
   CSP rules: no inline scripts or `onclick`, `data-action` wiring, vendored
   libraries only.

## Non-goals

- No change to Consent-Manager.
- No schema or API compatibility with Consent-Manager.
- No change to `audit_logs.user_id`. It already holds `security.pseudonym()`
  output (keyed by `TSI_LOOKUP_SALT`) and feeds the hash chain; re-keying it
  would break every stored `current_log_hash`.
- No key rotation tooling. `DB_ENCRYPTION_KEY` stays "do not rotate after data
  exists", as documented today.
- No UI for p5's other API-only features (nominations, roles, etc.).

## Anti-goals (failure even if it "works")

- Any principal identifier still readable in plaintext from a table, an export
  file, a log line or a default API response to the console.
- A reveal that returns plaintext without a committed audit row.
- Breaking the audit hash chain or `verify_audit_chain`, including across
  archived partitions.
- Weakening p5's existing protections: the `consent_records` and `audit_logs`
  append-only triggers, the CSP, API-key scoping, principal-token scoping.

## Constraints

- **Pre-production.** No live data. Migrations may expand and contract in one
  step. Developer databases may still have rows, so each migration backfills
  when `app.enc_key` is set and **raises an exception (aborts) if rows exist
  but the key is not set**, rather than dropping plaintext it could not copy.
- **Migration numbering** continues after `30`: `31_` onward, one concern per
  file, idempotent where Postgres allows.
- **Append-only triggers.** Backfills that `UPDATE consent_records` must run with
  `SET LOCAL tsi.consent_maintenance = 'on'` (see `db/25_p9_remediation.sql`).
  The `audit_logs` triggers from `db/19_audit_ledger_integrity.sql` must be
  re-created on the new partitioned table and verified to apply to partitions.
- **Encryption helpers.** Use the existing `db.enc_expr()`, `db.bind_encrypt()`,
  `db.decrypt_col()`, and add a principal-ID HMAC helper alongside
  `db.hmac_expr()` / `db.bind_hmac()` that trims without lowercasing. The
  Python helper and the SQL backfill must compute byte-identical HMACs.
- **Erasure.** Code that currently overwrites `consent_records.ip_address` with
  `'0.0.0.0'` on erasure (`services/compliance.py`) must overwrite
  `ip_address_enc` instead, still under the maintenance setting.
- **Lint and CI.** `ruff check`, `ruff format --check` and the existing
  `pytest tests` / `pytest pentest` suites must pass.

## Decided

- Python rewrite inside p5's existing structure; Consent-Manager's Java is
  reference only.
- New migrations start at `31`.
- Only p5 changes.
- **Identifiers inside free-text and JSON.** From now on, `audit_logs.context_details`
  stores pseudonyms (`security.pseudonym()`) instead of raw principal
  identifiers, and `audit_logs.source_ip` stores an encrypted value for
  principal-originated events. Because both are hash-chained and p5 is
  pre-production, developer databases reset `audit_logs` (the chain restarts
  from genesis) rather than rewriting old rows; the migration documents this.
  Webhook and alert payloads sent to processors keep plaintext identifiers,
  because processors must act on them; delivery queues keep their current
  purge-after-delivery retention. `jobs.input_payload` must not carry raw
  principal identifiers (store the HMAC or the record ID instead).
- **Who may reveal.** `reveal_user_id` is allowed for DPO (own fiduciary only)
  and platform ADMIN (any fiduciary). OPERATOR and AUDITOR are refused, and the
  console hides the Reveal control for them. Every reveal is audit-logged and
  rate-limited regardless of role.

## Calls made by Claude (check these)

- **Column coverage is wider than Consent-Manager's.** Besides Consent-Manager's
  list (`consent_records.user_id`, `data_principal.user_id`/`guardian_id`,
  `grievances.user_id`, `purge_requests.user_id`, `consent_validations.user_id`,
  `breach_affected_principals.user_id`,
  `parental_verification_logs.child_principal_id`/`guardian_principal_id`,
  `notifications.recipient_id`), the p5-only tables that hold a principal
  identifier are covered too: `data_correction_requests.user_id`,
  `reconsent_requests.user_id`, `notification_deliveries.recipient_id`,
  `nominations` principal/nominee identifiers. The builder confirms the full
  list by inventory before writing migration 31.
- **Masking.** Operator (console) responses return masked identifiers by
  default (email `a***@d***.com`-style, phone keeps a short prefix), with
  `reveal_user_id` as the only way to see plaintext.
- **Who gets plaintext.** Any caller that must act on the identity gets it
  decrypted: API-key app callers for their own principals; processor apps with
  PURGE scope on `list_purge_requests` / `get_purge_request` /
  `confirm_purge_status`; processor webhooks and alerts; a principal calling
  `export_consent_history` for their own history.
- **Exports.** DPO/console export jobs write masked identifiers.
- **Case sensitivity.** Principal IDs stay case-sensitive as today. The
  principal-ID HMAC normalises with `trim()` only, not `lower()` (unlike
  `email_hmac`), so `ABC123` and `abc123` remain different principals and
  `security.pseudonym()` joins still line up.
- **Search.** Console filters on principal ID become exact-match (via HMAC).
  Substring search on principal IDs is no longer possible.
- **Erased rows.** Wherever erasure today writes an `erased:<token>`
  placeholder into a principal-ID column, it writes the encrypted and HMAC'd
  form of that placeholder instead.
- **Retention window** for audit archiving: current year plus two prior years
  stay live, matching Consent-Manager. Configurable through an env var with
  that default.
- **Reveal rate limit:** 20 per operator per rolling minute, DB-backed through
  p5's existing `throttle.py` rather than in-memory.
- **Order of work:** grievance channel, audit partitioning and archive, PII
  encryption, evidence and IP encryption, `reveal_user_id`,
  `get_parental_verification`, `get_consent_audit_trail`, then UI. Each lands
  with its tests.

## Left to the builder

- Exact masking function placement (a new helper next to `security.pseudonym`
  is expected).
- Index set on `_hmac` columns (mirror every index that existed on the
  plaintext column).
- How `verify_audit_chain` and the evidence-certificate trail read across live
  and archived partitions (Consent-Manager uses the registry to UNION archived
  tables in).
- Test split between unit tests and `tests/test_integration_db.py`.
- Which Consent-Manager commits to read for UI behaviour: `2f22587`, `a182dbc`,
  `f0d65af`, `da3146b` and the `Pii.java` / `PiiMasking.java` sources.

## Done when

- `information_schema.columns` shows no plaintext principal identifier,
  `ip_address`, `verification_ref_id` or `proof_metadata` column.
- A fresh `docker compose up` initialises cleanly through migration `3x`.
- A consent can be recorded, listed (masked), revealed (audit row present),
  withdrawn per purpose, and erased, end to end.
- `verify_audit_chain` passes before and after an archive sweep.
- CI is green.
