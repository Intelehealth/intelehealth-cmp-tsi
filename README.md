# Intelehealth CMP (TSI) — DPDP Consent Management System

Standalone FastAPI port of the TSI DPDP Consent Management System. It serves the existing static consoles and talks to PostgreSQL with `pgcrypto` for encrypted PII.

This repository does **not** include the original Java servlet sources.

## Layout

| Path | Purpose |
| --- | --- |
| `python_port/` | FastAPI application |
| `web/` | Static UI and JSON Schema validators |
| `db/` | PostgreSQL init scripts (applied on first database start) |
| `.env.example` | Environment template (copy to `.env`, never commit `.env`) |
| `docker-compose.yml` | App, background worker, and Postgres for local use |
| `CHANGELOG.md` | Release notes for this branch (P1/P2) |
| `.github/workflows/main.yml` | CI: Ruff, tests, Docker build |

## Quick start (Docker)

On Windows, `scripts\local\deploy.ps1` does all of the steps below, including migrating an existing database, with a backup taken first. See [docs/LOCAL_DEPLOYMENT.md](docs/LOCAL_DEPLOYMENT.md) for the full plan: preflight, first admin, smoke test, rollback.

Docker Compose uses **local-only** default passwords and keys if you have no `.env`. That is convenient for a laptop. It is not safe on a shared or public machine.

```bash
docker compose up -d --build
```

App: <http://localhost:8091>
Postgres (loopback only): `localhost:5434`

Watch first boot:

```bash
docker compose logs -f python_app
```

Open `/console/setup/init.html` to create the first admin (password ≥ 12 characters). You need the server `BOOTSTRAP_TOKEN` (header `X-Bootstrap-Token` or `bootstrap_token` in the body).

The **`python_worker`** service must be running for notification delivery, webhooks, purpose closure, escalations, retention sweeps, and queued export jobs.

## Local Python (without Docker for the app)

You still need Postgres (the Compose `postgres_db` service is enough).

```bash
cp .env.example .env
# Set POSTGRES_PASSWD, JWT_SECRET, DB_ENCRYPTION_KEY, TSI_LOOKUP_SALT, and BOOTSTRAP_TOKEN.
# Generate secrets: openssl rand -hex 32

cd python_port
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn dpdpcms_py.main:app --host 127.0.0.1 --port 8080
```

On Windows, activate with `.venv\Scripts\activate`.

Point `POSTGRES_HOST` at your Postgres (Compose maps it to host port **5434**). Align `ALLOWED_ORIGINS` with the URL you open in the browser.

## Environment

| Variable | Role |
| --- | --- |
| `POSTGRES_HOST` | `postgresql://host:port` (JDBC-style `jdbc:postgresql://...` is still accepted) |
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWD` | Database connection |
| `JWT_SECRET` | HS256 signing key (min 32 characters) |
| `DB_ENCRYPTION_KEY` | `pgcrypto` PII key — **do not rotate** after data exists |
| `TSI_LOOKUP_SALT` | HMAC salt for audit pseudonyms |
| `BOOTSTRAP_TOKEN` | One-time gate for Super-Admin bootstrap (`/api/v1/bootstrap/setup`); min 32 characters |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins |
| `TSI_DPDP_CMS_ENV` | One of `local`, `test`, `staging`, `production` (case-insensitive; anything else refuses to start). `local` enables `/docs`; the others hide OpenAPI and require SSL to Postgres |
| `BRAND_NAME` | Optional UI label, max 12 characters |
| `TSI_EXPORT_PATH` | Export/report directory |

The process refuses to start if secrets are missing, too short, or still set to `change-me`.

Worker and delivery options (`WORKER_POLL_SECONDS`, SMTP, gateways, retry limits, escalation windows) are documented in `.env.example` and [python_port/README.md](python_port/README.md).

## Development & CI

From the repo root (Python 3.12+):

```bash
pip install -r python_port/requirements.txt ruff pytest
export POSTGRES_HOST=postgresql://localhost:5434 POSTGRES_DB=ci POSTGRES_USER=ci
export POSTGRES_PASSWD=ci-only-password-not-real-1234567890
export JWT_SECRET=ci-only-jwt-secret-not-real-1234567890abcd
export DB_ENCRYPTION_KEY=ci-only-enc-key-not-real-1234567890abcdef
export TSI_LOOKUP_SALT=ci-only-salt-not-real-1234567890abcdefgh
export BOOTSTRAP_TOKEN=ci-only-bootstrap-token-not-real-1234567890ab
export TSI_DPDP_CMS_ENV=local
ruff check python_port
cd python_port && pytest -q
```

GitHub Actions (workflow in `.github/workflows/main.yml`) runs on pushes and pull requests to **`p1_changes`**: Ruff lint, byte-compile, `import dpdpcms_py.main`, pytest, and a Docker image build. CI injects the same placeholder secrets as above (including `BOOTSTRAP_TOKEN`).

More detail: [python_port/README.md](python_port/README.md).

## Database upgrades

Postgres init scripts in `db/` run **once** when the data volume is first created (`docker-entrypoint-initdb.d`). File order is lexical (`01_init.sql` … `34_principal_pii_encryption.sql`).

| Script | Purpose |
| --- | --- |
| `13_breach_notification_deadline.sql` | Board notification deadline on breach incidents |
| `14_nomination_data_correction.sql` | Nominations and data-correction request tables |
| `15_p1_consent_lifecycle_alerts.sql` | Purpose lifecycle, alerts, re-consent, delivery/webhook queues |
| `16_p2_roles_mfa_retention.sql` | Roles, operator MFA columns, retention policies, grievance references |
| `17_defect_fixes.sql` | Principal OTP store, per-tenant roles + extended built-in permissions, TOTP replay/lockout columns, purge status CHECK |
| `18_brd_traceability.sql` | Append-only consent metadata, guardian verification status, purge action/legal hold/evidence, grievance feedback and attachments, token revocation |
| `19_audit_ledger_integrity.sql` | Trigger that makes `audit_logs` append-only (UPDATE, DELETE and TRUNCATE fail) |
| `20_security_gaps.sql` | Attempt throttles (login/recovery), single-use SSO nonces, rights-app OTP mode default |
| `21_defect_remediation_p6.sql` | Throttle backoff column, one-off clear of pre-encryption OTP webhook payloads (terminal rows only) |
| `22_sec18_null_fiduciary_block.sql` | Deactivates pre-existing non-ADMIN operators with a NULL `fiduciary_id` (SEC-18) |
| `23_notification_delivery_floor.sql` | Database-enforced one-year DELETE floor on `notification_deliveries` (P5-07) |
| `24_p8_remediation.sql` | UPDATE floor on delivery personal-data columns, notification delete floor, audit chain index and background verification table, notification context |
| `25_p9_remediation.sql` | Append-only trigger on `consent_records` (P9-05), `CANCELLED` purge status (P9-04), grievance `language` column (GR-03) |
| `26_p10_remediation.sql` | Canonical purpose ids with canonicalising triggers (P10-04/05/09), one active consent per principal per policy (P10-11), per-processor webhooks (CW-08), legacy template names merged (NT-02), narrower `consent_records` maintenance opt-in (P9-05) |
| `27_p11_remediation.sql` | Maintenance guard reads "granted" exactly as the consent gate does and rejects a non-array payload (P11-01/02); last two legacy template names archived with the live type each maps to, and removed (P11-09, P12-07) |
| `28_security_coverage.sql` | Breach Board-intimation columns (s.8(6)), worker heartbeat (Rule 6(1)(d)), row-level security for any non-application role granted `tsi_tenant_reader` (Rule 6(1)(b)) |
| `29_p12_remediation.sql` | Board intimation asserted time and Rule 7 report fields (P12-04), tenant readers mapped in `tsi_reader_tenants` (P12-05), `consent_policies` keyed per tenant (P12-06), legacy template text taken back out of live types (P12-07), audit purpose index (LG-05) |
| `30_p13_remediation.sql` | Tenant-reader RLS consults the security-barrier view `tsi_reader_my_tenants` (own mappings only); the role-taking helper `tsi_reader_may_see` is dropped (P13-03) |
| `31_grievance_channel.sql` | `grievances.channel` (PORTAL, EMAIL, PHONE, LETTER, IN_PERSON, OTHER): how a grievance reached the fiduciary; a DPO logs offline ones with the real channel |
| `32_partition_audit_logs.sql` | `audit_logs` range-partitioned by year with a DEFAULT partition; pre-production ledger reset (the old table is kept as `audit_logs_legacy_pre32`, its rows are not copied and the hash chain restarts from genesis) |
| `33_audit_archive_registry.sql` | `audit_log_archive_registry`: yearly partitions older than `AUDIT_LIVE_YEARS` that the worker detached into `audit_logs_y<YYYY>_archive` tables (never deleted; still read by verification, search and certificates) |
| `34_principal_pii_encryption.sql` | Every Data Principal identifier column (consent, principal, grievance, purge, validation, breach, parental, notification, delivery, correction, re-consent, nomination, alert, certificate tables) replaced by `<col>_enc` (pgcrypto) + `<col>_hmac` (lookup key); keys and indexes move to `_hmac`. Needs `app.enc_key` set when any of those tables has rows (fails before changing anything otherwise) |

**Existing deployments** that already have a Postgres volume must apply `13`–`34` manually (each script is idempotent). Example:

```bash
for f in db/13_breach_notification_deadline.sql db/14_nomination_data_correction.sql \
         db/15_p1_consent_lifecycle_alerts.sql db/16_p2_roles_mfa_retention.sql \
         db/17_defect_fixes.sql db/18_brd_traceability.sql \
         db/19_audit_ledger_integrity.sql db/20_security_gaps.sql \
         db/21_defect_remediation_p6.sql db/22_sec18_null_fiduciary_block.sql \
         db/23_notification_delivery_floor.sql db/24_p8_remediation.sql          db/25_p9_remediation.sql \
         db/26_p10_remediation.sql db/27_p11_remediation.sql db/28_security_coverage.sql \
         db/29_p12_remediation.sql db/30_p13_remediation.sql \
         db/31_grievance_channel.sql db/32_partition_audit_logs.sql \
         db/33_audit_archive_registry.sql db/34_principal_pii_encryption.sql; do
  psql "$DATABASE_URL" -f "$f"
done
```

Until those scripts are applied, P1/P2 API calls that touch the new tables will fail even if `/healthz` returns ok (health check does not yet verify every new table).

## API surface

Routing matches the original servlet filter:

- `/api/v1/admin/{service}`
- `/api/v1/client/{service}`
- `/api/v1/public/{service}`
- `/api/v1/bootstrap/setup` — first-time admin only (`initial_setup`)
- `/api/v1/{service}` — legacy admin path

P1 additions (see the MeitY/NeGD BRD API traceability workbook, "New APIs to Build"):

| Endpoint | `_func` | Purpose |
| --- | --- | --- |
| `/api/v1/admin/purpose` | `set_purpose_state`, `close_purpose`, `list_purpose_lifecycle` | Purpose lifecycle — the substitute for consent renewal (PL-01..03). Closing a purpose raises purge requests and de-identification signals. |
| `/api/v1/client/alerts` | `notify_alert`, `acknowledge_alert`, `list_alerts` | The BRD-named `/api/alerts/notify`: consent-change alerts for fiduciaries and processors (NT-06..08). |
| `/api/v1/admin/policy` | `notify_policy_change`, `request_reconsent` | On publishing a materially changed policy, notify affected principals and collect fresh affirmative consent (CU-02, CU-03). `publish_policy` runs the notification automatically. |
| `/api/v1/admin/policy` (`create_policy`/`update_policy`) | — | Every purpose must now declare `duration_type` (`OPEN_ENDED`/`TIME_BOUND`); time-bound purposes require `consent_expiry_days` (PL-01). |

P1 infrastructure:

- **Background worker** — `python -m dpdpcms_py.worker` (see Compose `python_worker`). Runs notification delivery, webhook dispatch, time-bound purpose closure, alert/grievance escalation, the retention sweep, and queued export jobs.
- **Notification delivery adapter** — delivers `notifications` rows by email (SMTP), SMS/push (gateway webhooks, SSRF-guarded); in-app delivery is the row itself. Delivery attempts are tracked in `notification_deliveries`.
- **Webhook dispatcher** — HMAC-signed, SSRF-guarded dispatch of queued events to `webhook_configs`; tracked in `webhook_deliveries`.

**P2 additions**

| Endpoint | `_func` (examples) | Purpose |
| --- | --- | --- |
| `/api/v1/admin/retention` | `create_retention_policy`, `list_retention_policies`, `validate_completeness` | Administrator-configured retention (DD-03); worker sweep prefers these rules |
| `/api/v1/admin/role` | `create_role`, `list_roles`, `set_role_permissions`, `delete_role` | Custom roles; built-in `AUDITOR` for read-only assurance |
| `/api/v1/admin/operator` | `enrol_mfa`, `verify_mfa` | TOTP MFA for console operators (SA-06); audit reads require MFA when enabled |
| `/api/v1/client/consent` | `export_consent_history` | Principal CSV export of own consent history (UD-04) |
| `/api/v1/client/grievance` | `submit_grievance` (returns `reference_number`) | Human-quotable grievance reference; optional `consent_record_id` link |
| `/api/v1/client/rights` | `create_nomination`, `list_nominations`, `submit_correction`, … | Nomination and correction rights |

JSON request bodies are validated against `web/WEB-INF/validator/{_func}.jschema` when a schema exists.

### Client authentication

Two client auth modes share `/api/v1/client/{service}`:

| Mode | Headers | Scope |
| --- | --- | --- |
| **Integrator API key** | `X-API-Key`, `X-API-Secret` | Bound to one fiduciary; permissions `READ` / `WRITE` / `PURGE` per function |
| **Principal JWT** | `Authorization: Bearer …` (from `principal_login`) | Bound to one `user_id` within the fiduciary; cannot call PURGE or raise alerts; read/write paths enforce the token subject |

Admin and bootstrap routes use operator JWT or `BOOTSTRAP_TOKEN` respectively. See [CHANGELOG.md](CHANGELOG.md) for the full feature list.

## Production deployment

1. Copy `.env.example` → `.env` and set unique secrets (`openssl rand -hex 32` for each).
2. Set `TSI_DPDP_CMS_ENV` to `staging` or `production` (disables `/docs`, requires SSL to Postgres). Other values refuse to start.
3. Set `ALLOWED_ORIGINS` to your real console origins.
4. Run DB migrations `13`–`23` on existing databases (see [Database upgrades](#database-upgrades)).
5. Run **two processes**: `uvicorn dpdpcms_py.main:app` and `python -m dpdpcms_py.worker` (or Compose `python_app` + `python_worker`).
6. Configure SMTP and/or SMS/push gateway URLs if off-channel notification delivery is required.
7. Do **not** rotate `DB_ENCRYPTION_KEY` after encrypted data exists.

## Security notes

- Compose default secrets are for local development only.
- Postgres is published on `127.0.0.1:5434` by default, not on all interfaces.
- Never change `DB_ENCRYPTION_KEY` after the database has encrypted rows.
- Keep `TSI_DPDP_CMS_ENV` off `local` in any deployed environment so `/docs` is disabled.
- Set `OUTBOUND_ALLOWED_HOSTS` to the approved in-India destinations (Rule 14); outside `local` the app refuses to start without it. Monitor `/healthz/worker` as well as `/healthz` (set `HEALTHZ_TOKEN` and send it as `X-Health-Token` for detail).
- The Rule 6 control map, with an owner and a record for each control the repo cannot enforce, is [docs/security/ISMS_CONTROL_MAP.md](docs/security/ISMS_CONTROL_MAP.md).

To report a vulnerability, see [SECURITY.md](SECURITY.md). Please do not open public issues for security problems.

## License

This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. See `LICENSE`. If a copy of the MPL was not distributed with this file, You can obtain one at <https://mozilla.org/MPL/2.0/>.
