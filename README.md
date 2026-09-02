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

Open `/console/setup/init.html` to create the first admin (password ≥ 12 characters).

## Local Python (without Docker for the app)

You still need Postgres (the Compose `postgres_db` service is enough).

```bash
cp .env.example .env
# Set POSTGRES_PASSWD, JWT_SECRET, DB_ENCRYPTION_KEY, and TSI_LOOKUP_SALT.
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

## Security notes

- Compose default secrets are for local development only.
- Postgres is published on `127.0.0.1:5434` by default, not on all interfaces.
- Never change `DB_ENCRYPTION_KEY` after the database has encrypted rows.
- Keep `TSI_DPDP_CMS_ENV` off `local` in any deployed environment so `/docs` is disabled.

To report a vulnerability, see [SECURITY.md](SECURITY.md). Please do not open public issues for security problems.

## License

This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. See `LICENSE`. If a copy of the MPL was not distributed with this file, You can obtain one at <https://mozilla.org/MPL/2.0/>.
