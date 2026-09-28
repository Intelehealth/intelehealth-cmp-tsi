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
| `docker-compose.yml` | App + Postgres for local use |

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

## Security notes

- Compose default secrets are for local development only.
- Postgres is published on `127.0.0.1:5434` by default, not on all interfaces.
- Never change `DB_ENCRYPTION_KEY` after the database has encrypted rows.
- Keep `TSI_DPDP_CMS_ENV` off `local` in any deployed environment so `/docs` is disabled.

To report a vulnerability, see [SECURITY.md](SECURITY.md). Please do not open public issues for security problems.

## License

This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. See `LICENSE`. If a copy of the MPL was not distributed with this file, You can obtain one at <https://mozilla.org/MPL/2.0/>.
