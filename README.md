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
| `TSI_DPDP_CMS_ENV` | `local` enables `/docs`; anything else hides OpenAPI and prefers SSL to Postgres |
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

Postgres init scripts in `db/` run **once** when the data volume is first created (`docker-entrypoint-initdb.d`). File order is lexical (`01_init.sql` … `16_p2_roles_mfa_retention.sql`).

| Script | Purpose |
| --- | --- |
| `13_breach_notification_deadline.sql` | Board notification deadline on breach incidents |
| `14_nomination_data_correction.sql` | Nominations and data-correction request tables |
| `15_p1_consent_lifecycle_alerts.sql` | Purpose lifecycle, alerts, re-consent, delivery/webhook queues |
| `16_p2_roles_mfa_retention.sql` | Roles, operator MFA columns, retention policies, grievance references |

**Existing deployments** that already have a Postgres volume must apply `13`–`16` manually (each script is idempotent). Example:

```bash
for f in db/13_breach_notification_deadline.sql db/14_nomination_data_correction.sql \
         db/15_p1_consent_lifecycle_alerts.sql db/16_p2_roles_mfa_retention.sql; do
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
2. Set `TSI_DPDP_CMS_ENV` to anything **other than** `local` (disables `/docs`, prefers SSL to Postgres).
3. Set `ALLOWED_ORIGINS` to your real console origins.
4. Run DB migrations `13`–`16` on existing databases (see [Database upgrades](#database-upgrades)).
5. Run **two processes**: `uvicorn dpdpcms_py.main:app` and `python -m dpdpcms_py.worker` (or Compose `python_app` + `python_worker`).
6. Configure SMTP and/or SMS/push gateway URLs if off-channel notification delivery is required.
7. Do **not** rotate `DB_ENCRYPTION_KEY` after encrypted data exists.

## Security notes

- Compose default secrets are for local development only.
- Postgres is published on `127.0.0.1:5434` by default, not on all interfaces.
- Never change `DB_ENCRYPTION_KEY` after the database has encrypted rows.
- Keep `TSI_DPDP_CMS_ENV` off `local` in any deployed environment so `/docs` is disabled.

To report a vulnerability, see [SECURITY.md](SECURITY.md). Please do not open public issues for security problems.

## License

This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. See `LICENSE`. If a copy of the MPL was not distributed with this file, You can obtain one at <https://mozilla.org/MPL/2.0/>.
