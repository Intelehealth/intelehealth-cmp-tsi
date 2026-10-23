# install-helper: Ubuntu installation scripts

Scripts that install the TSI DPDP CMS (FastAPI app, background worker, PostgreSQL with `pgcrypto`) on Ubuntu 22.04 or 24.04.

There are two ways to install:

| | `install.sh` (native, for servers) | `install-docker.sh` (Compose, for laptops) |
| --- | --- | --- |
| Runtime | systemd services, Python 3.12 venv, PostgreSQL 15 from PGDG | The repo's `docker-compose.yml` |
| TLS | nginx, with a Let's Encrypt or self-signed certificate, or your own nginx elsewhere (`TLS_MODE=external`) | None (loopback HTTP on 8091) |
| Environment | `production` by default | `local` |
| Encryption key | Set per session and never stored in the database | Stored as a database default by `db/03z_enc_key.sh` |
| Backups | Daily `pg_dump` and exports archive (systemd timer) | Manual: `manage.sh backup` |
| Firewall | ufw allows SSH, 80 and 443 | Not configured |

## Native install

```bash
git clone <repo> && cd intelehealth-cmp-tsi
cp install-helper/install.conf.example install-helper/install.conf
nano install-helper/install.conf      # DOMAIN, TLS_MODE, LETSENCRYPT_EMAIL, OUTBOUND_ALLOWED_HOSTS
sudo bash install-helper/install.sh
sudo bash install-helper/bootstrap-admin.sh admin@example.in
sudo bash install-helper/smoke-test.sh admin@example.in
```

If you don't set `ALLOWED_ORIGINS`, it defaults to `https://$DOMAIN`. Outside `APP_ENV=local`, `OUTBOUND_ALLOWED_HOSTS` is required, and `*` is refused in production. These are the app's own rules (`config.py`), and the preflight checks them before anything is installed.

### nginx outside the container (`TLS_MODE=external`)

Use this when the installer runs inside an LXC/systemd container and nginx on the host already serves the domain and its certificate. Nothing about nginx, certbot or Let's Encrypt is installed or touched here.

```ini
DOMAIN=cmp.intelehealth.org     # CORS origin and printed URLs only
TLS_MODE=external
APP_BIND_HOST=0.0.0.0            # or this container's IP
EXTRA_TRUSTED_PROXY_IPS=10.0.3.1 # host bridge IP your nginx connects from
```

uvicorn listens on `APP_BIND_HOST:APP_PORT`. With `ENABLE_UFW=yes`, only `EXTRA_TRUSTED_PROXY_IPS` can reach that port, and the same IPs are trusted for `X-Forwarded-For`. Point the host nginx at `http://<container IP>:8080`. `07-nginx.sh` prints the `location` blocks it needs: the proxy headers, a 404 on `/docs` and `/openapi.json`, and, after `bootstrap-admin.sh`, a 403 on `/api/v1/bootstrap/`.

`install.sh` runs the numbered steps in order. Each step can be re-run on its own, and re-running is safe: secrets and data are kept.

| Script | Does |
| --- | --- |
| `00-preflight.sh` | Checks the OS, architecture, memory, disk, ports, DNS and `install.conf`. Changes nothing |
| `01-system-packages.sh` | Python 3.12 (deadsnakes PPA if the release lacks it), nginx, certbot, NTP, unattended security upgrades, ufw |
| `02-secrets.sh` | Creates the `tsi` service user and the directories, and writes `/etc/tsi-cms/tsi-cms.env` (`0640 root:tsi`) with generated secrets |
| `03-postgres.sh` | PostgreSQL 15 from PGDG, loopback only, `ssl=on`, SCRAM, TLS-only `pg_hba` rules for the app role, statement and parameter logging off. Creates the owner role, the database, `uuid-ossp`/`pgcrypto` and `tsi_tenant_reader` |
| `04-app.sh` | Copies `python_port/`, `web/` and `db/` to `/opt/tsi-cms` (root-owned and read-only), creates a venv and runs `pip install --require-hashes -r requirements.lock`, then an import check |
| `05-migrate.sh` | Fresh database: runs every `db/*.sql`. Existing database: takes a backup, then runs `13`–latest. Then verifies the ledger and retention triggers |
| `06-services.sh` | Writes and starts `tsi-cms-app` (uvicorn on `APP_BIND_HOST:APP_PORT`, `127.0.0.1:8080` by default) and `tsi-cms-worker`, both sandboxed by systemd |
| `07-nginx.sh` | Sets up TLS 1.2/1.3, the HTTP→HTTPS redirect and the reverse proxy. Blocks `/docs` and `/openapi.json`. Skipped for `TLS_MODE=external`/`none` |
| `08-backups.sh` | Installs `/usr/local/sbin/tsi-cms-backup` and a daily timer (`--now` takes one backup immediately) |

Other scripts:

- **`bootstrap-admin.sh <email>`** creates the first Super-Admin. It then rotates `BOOTSTRAP_TOKEN` to a value nobody keeps and has nginx return 403 on `/api/v1/bootstrap/`.
- **`smoke-test.sh [email]`** checks the services, health endpoints (including the worker heartbeat), TLS, loopback-only listeners, ledger triggers, TLS on database connections, that no key is stored in the database, and file permissions.
- **`upgrade.sh`**: run it after `git pull`. It stops the services, syncs the code and dependencies, backs up, migrates, restarts and runs a health check. If a step fails, the services stay stopped and the pre-migration dump is your rollback point.

### Layout on the host

| Path | What |
| --- | --- |
| `/opt/tsi-cms/{python_port,web,db,venv}` | Code and dependencies (root-owned) |
| `/etc/tsi-cms/tsi-cms.env` | All settings and secrets. Add SMTP, SSO, gateways etc. here (see `.env.example`), then run `systemctl restart tsi-cms-app tsi-cms-worker` |
| `/var/lib/tsi-cms/exports` | Exports and grievance attachments (`TSI_EXPORT_PATH`) |
| `/var/backups/tsi-cms` | Daily `*.dump` and `exports-*.tar.gz` files (`0700 root`) |

Day-to-day commands:

```bash
journalctl -u tsi-cms-app -u tsi-cms-worker -f
systemctl restart tsi-cms-app tsi-cms-worker
sudo -u postgres psql tsi_cms
pg_restore -l /var/backups/tsi-cms/<file>.dump        # inspect a backup
```

### Deliberate choices

- **The encryption key is never stored in the database.** The Docker init runs `ALTER DATABASE … SET app.enc_key`, which puts the key into every dump. Here migrations get `app.enc_key` and `app.lookup_key` through `PGOPTIONS` for their own session only, and the app sets them per connection (`db.py`). Backups therefore hold ciphertext only. See `docs/security/AWS_INFRASTRUCTURE_SECURITY.docx`, "Key handling".
- **The app connects as the schema owner**, as in Compose. The worker needs owner rights to create and detach yearly `audit_logs` partitions (db/32, db/33). That also means the owner could disable the append-only triggers, so keep shell access to this host restricted.
- **uvicorn runs with `--no-proxy-headers`.** The app resolves the client IP itself from `X-Forwarded-For`, trusting only `TRUSTED_PROXY_IPS` (nginx on loopback, plus `EXTRA_TRUSTED_PROXY_IPS` for a load balancer in front).
- **`CERTIFICATE_SIGNING_KEY` is set explicitly**, so evidence certificates don't depend on `DB_ENCRYPTION_KEY`.

### Before real data

1. Back up `/etc/tsi-cms/tsi-cms.env` **offline, away from the database backups**. If you lose `DB_ENCRYPTION_KEY`, you lose who every consent belongs to. Never change `DB_ENCRYPTION_KEY`, `TSI_LOOKUP_SALT` or `PII_LOOKUP_KEY` once data exists (`docs/security/KEY_MANAGEMENT.md`).
2. Copy `/var/backups/tsi-cms` off the host to storage in India (Rule 14), and test a restore.
3. Enrol MFA for every operator, and configure SSO (`SSO_*`) if you use an IdP.
4. Fill in `docs/security/OUTBOUND_DESTINATIONS.md` so it matches `OUTBOUND_ALLOWED_HOSTS`.
5. Point the monitoring at `/healthz` and `/healthz/worker`. Send `X-Health-Token` (the `HEALTHZ_TOKEN` in the env file) to get the detail.

## Docker install (evaluation only)

```bash
sudo bash install-helper/install-docker.sh --add-user "$USER"
```

This installs Docker Engine and the Compose plugin from Docker's apt repository, then runs the repo's `scripts/local/shell_scripts/init-env.sh` and `deploy.sh`. It publishes the app on `127.0.0.1:8091` only, because Docker-published ports bypass ufw. Don't put real personal data in this stack.

## Line endings

The scripts must have LF line endings. The repo's `.gitattributes` handles this on checkout. If you copy the folder from Windows by other means, run `sed -i 's/\r$//' install-helper/*.sh` first.
