# Local deployment plan — branch `brd-traceability-fixes`

How to run the TSI DPDP CMS Python port on a Windows laptop with Docker Desktop, including the
database upgrade this branch needs. Everything here is **local-only**: the secrets, ports and
`DUMMY_OTP` portal login are not suitable for a shared or public host.

## 1. What runs

| Container | Image | Host port | Purpose |
|---|---|---|---|
| `tsi_dpdp_cms_py_db` | `postgres:15-alpine` | `127.0.0.1:5434` | Database. `db/*.sql` run once, when the volume is first created. |
| `tsi_dpdp_cms_py_server` | `tsi-dpdp-cms-python:local` | `8091` | FastAPI API, admin console (`/`), rights portal (`/rights/`). |
| `tsi_dpdp_cms_py_worker` | same image | — | Notification delivery, webhooks, purpose closure, escalations, retention sweep, export jobs. |

Volumes: `<project>_postgres_py_data` (database) and `<project>_tsi_py_reports_data` (exports and
grievance attachments, mounted at `/var/lib/tsi/exports/`). The project name is the folder name,
`intelehealth-cmp-tsi`.

## 2. Prerequisites

- Docker Desktop running (engine 24+, Compose v2).
- PowerShell 5.1 or 7. If scripts are blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`,
  or run each one with `powershell -ExecutionPolicy Bypass -File <script>`.
- Free ports 8091 and 5434.
- Optional: Python 3.12+ on the host, to run the unit tests (`manage.ps1 test`).

All scripts live in `scripts/local/` and are run from the repository root. Each one exists twice
with the same behaviour: PowerShell (`.ps1`, Windows) and bash (`.sh`; Linux, macOS, Git Bash, WSL).
The bash versions also need `curl`.

| Step | PowerShell | bash |
|---|---|---|
| Secrets | `.\scripts\local\init-env.ps1 [-Force]` | `scripts/local/init-env.sh [--force]` |
| Preflight | `.\scripts\local\preflight.ps1` | `scripts/local/preflight.sh` |
| Deploy | `.\scripts\local\deploy.ps1 [-SkipBuild] [-Migrate]` | `scripts/local/deploy.sh [--skip-build] [--migrate]` |
| Migrate | `.\scripts\local\migrate.ps1 [-Only <file>]` | `scripts/local/migrate.sh [file ...]` |
| First admin | `.\scripts\local\bootstrap-admin.ps1 -Email <e>` | `scripts/local/bootstrap-admin.sh <email> [name]` |
| Smoke test | `.\scripts\local\smoke-test.ps1 [-Email <e>]` | `scripts/local/smoke-test.sh [email]` |
| Operations | `.\scripts\local\manage.ps1 <action>` | `scripts/local/manage.sh <action>` |

The examples below use PowerShell; swap in the bash equivalent from the table.

## 3. Phase 0 — clear conflicts on this machine (one-time)

Run `.\scripts\local\preflight.ps1`. It checks Docker, `.env`, ports, the font files and migration 20,
and also checks container names. Compose gives each container a fixed `container_name`, so a stopped
container with the same name from **another checkout** blocks `docker compose up` here.

If it reports a name as taken by another project, free the name. Either command below keeps that
project's data volumes:

```powershell
cd <that checkout>; docker compose down     # from the other checkout
docker rm -f tsi_dpdp_cms_py_db tsi_dpdp_cms_py_server tsi_dpdp_cms_py_worker
```

Only `docker compose down -v` or `docker volume rm` deletes data.

> On this laptop on 7 Oct 2026, the stopped `tsi-fork-python-port` containers and volumes were
> removed. Its database was dumped first to
> `backups/predrop-tsi-fork-python-port_postgres_py_data-tsi_cms-*.dump`. This project's own old
> volume was empty (never initialised) and was dropped too, so the next deploy starts from a fresh
> database.

## 4. Phase 1 — prepare

1. **Secrets.** `.\scripts\local\init-env.ps1` creates `.env` from `.env.example` with generated
   64-character secrets. It does nothing if `.env` exists (the current `.env` already has all four
   secrets set). Keep `DB_ENCRYPTION_KEY` and `TSI_LOOKUP_SALT` unchanged once data exists: encrypted
   columns and pseudonymised ids depend on them.
2. **Optional settings** in `.env` now reach the containers (Compose loads `.env` through
   `env_file`; the values under `environment:` still win):
   - `DIGILOCKER_VERIFY_URL`: without it, DigiLocker guardian checks stay PENDING (CC-05).
   - `SMTP_*`, `SMS_GATEWAY_URL`, `PUSH_GATEWAY_URL`: real delivery. In-app delivery works without them.
   - `ATTACHMENT_MAX_BYTES`, `PURGE_COMPLETION_SLA_DAYS`, `SSO_*`.
3. **Tests (optional):** `.\scripts\local\manage.ps1 test`. Expected result: 173 passed.

## 5. Phase 2 — deploy

```powershell
.\scripts\local\deploy.ps1
```

Steps:

1. Runs preflight and stops on any failure.
2. Checks whether the database volume already exists.
   - **Fresh volume:** Postgres runs `01` to `20` itself on first start.
   - **Existing volume:** the init scripts will **not** run again, so the upgrade path below is used.
3. Builds the image (`-SkipBuild` reuses the last one), runs `docker compose up -d`, and waits for
   `/healthz`.
4. Existing volume only:
   1. `manage.ps1 backup` writes `backups\tsi_cms-<timestamp>.dump`. If the backup fails, nothing is migrated.
   2. `migrate.ps1` applies `13` to `20` in order (each is idempotent) and confirms that both
      `audit_logs` triggers exist.
   3. The app and worker restart on the migrated schema.
5. Prints the URLs and the next step.

To run the migrations on their own: `.\scripts\local\migrate.ps1`. For a single script:
`.\scripts\local\migrate.ps1 -Only 20_security_gaps.sql`.

## 6. Phase 3 — first Super-Admin (fresh database only)

```powershell
.\scripts\local\bootstrap-admin.ps1 -Email admin@example.org -Name "Super Admin"
```

The script prompts for the password twice (minimum 12 characters) and posts to
`/api/v1/bootstrap/setup` with `BOOTSTRAP_TOKEN` from `.env`. It does nothing if an admin already
exists. After signing in, enrol MFA from the console.

## 7. Phase 4 — verify

```powershell
.\scripts\local\smoke-test.ps1 -Email admin@example.org
```

Automated checks:

- All three containers are running.
- `/healthz` returns 200 and the console page is served.
- `/WEB-INF/...` returns 404 (CF-01).
- A mixed-case `_func` sent without credentials is refused (P4-02).
- Both `audit_logs` triggers exist, and `TRUNCATE audit_logs` is rejected; the test runs inside a
  rolled-back transaction (LG-04).
- Tables from migrations 15 to 18 are present.
- Operator login works, and `verify_audit_chain` reports `intact: true`. Rows written before this
  branch are counted as `legacy_rows_linkage_only`. If MFA is enabled on the account, the script
  skips this check and says so.
- The last 200 lines of the worker log contain no traceback.

Manual checklist for this branch's changes (console at http://localhost:8091/):

| Area | Check |
|---|---|
| Console escaping (CF-02) | Create a grievance whose subject is `<img src=x onerror=alert(1)>`. In DPO > Grievances it shows as text, and no alert appears. |
| Grievance attachments (D15) | Open a grievance, upload a PDF or PNG, download it, and confirm the file matches. |
| Consent PDF (UD-04) | Export a principal's consent history as PDF. Devanagari and Tamil text renders with no `?` characters. |
| Retention floor (SA-12) | Create a retention policy of 7 YEARS: accepted. 6 YEARS: rejected. |
| Closed purpose (PL-02) | Close a purpose. A new consent that declines or omits it is accepted; one that grants it gets 403. |
| Consent per policy (CW-03) | With two active policies, consent to both. Each stays active (`list_consent_history` with `status=ACTIVE`). |
| Wallet (P4-01) | Server side is fixed and covered by tests. The demo page `web/tour/dpdp-wallet.html` sends its `sync_token` in the request body instead of an `Authorization: Bearer` header, so its actions are still refused (401). Test with `curl` and a bearer token, or fix the page first. |

## 8. Day-to-day operations

```powershell
.\scripts\local\manage.ps1 status              # container state
.\scripts\local\manage.ps1 logs python_worker  # follow one service's logs
.\scripts\local\manage.ps1 stop | start | restart
.\scripts\local\manage.ps1 backup              # pg_dump -Fc to backups\
.\scripts\local\manage.ps1 psql                # SQL shell
.\scripts\local\manage.ps1 reset               # DELETES the database and exports volumes (asks first)
```

After pulling new code: run `deploy.ps1` again. It rebuilds the image, and it migrates only when the
volume existed before the run. For a new `db/NN_*.sql`, add the file to `$UpgradeMigrations` in
`common.ps1` and to the README upgrade loop.

## 9. Rollback

1. `manage.ps1 stop`.
2. Check out the previous commit and run `deploy.ps1 -SkipPreflight`.
3. If the schema must go back as well (the migrations only add things, so old code normally runs on
   the new schema), restore the backup into the database. Migration 19 forbids `DELETE` and
   `TRUNCATE` on `audit_logs`, so restore into an empty database instead:

   ```powershell
   .\scripts\local\manage.ps1 reset            # empty volume
   .\scripts\local\deploy.ps1 -SkipBuild       # recreate; init scripts run
   docker compose cp backups\<file>.dump postgres_db:/tmp/restore.dump
   docker compose exec postgres_db pg_restore -U tsi_admin -d tsi_cms --clean --if-exists /tmp/restore.dump
   ```

   Use your `POSTGRES_USER` and `POSTGRES_DB` values if you changed them.

## 10. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Conflict. The container name "/tsi_dpdp_cms_py_db" is already in use` | A container from another checkout. See Phase 0. |
| `/healthz` 503 `database schema is incomplete` | An existing volume that hasn't been migrated. Run `migrate.ps1`. |
| Login fails or decryption errors on an existing volume | `.env` has a different `DB_ENCRYPTION_KEY` or `TSI_LOOKUP_SALT` from the one the volume was created with. Restore the original values. |
| `audit_logs is append-only: DELETE is not permitted` | Migration 19 is working as intended. Nothing may change or prune audit rows. |
| Rights-portal login refused with `DUMMY_OTP` | `TSI_DPDP_CMS_ENV` is not `local`. Set it back, or configure an OTP webhook. |
| Worker logs `Webhook ... refused: ...` | A webhook URL is private or doesn't resolve. That is a failed attempt and the sweep continues (CC-09). |
| Scripts blocked by policy | `powershell -ExecutionPolicy Bypass -File .\scripts\local\deploy.ps1` |

## 11. Not covered locally

TLS, a reverse proxy, a secrets manager, Postgres backups off the laptop, and real OTP, SMS and email
providers are needed for any shared environment. Cookie consent (BRD 4.2) is out of scope (DD-04).
