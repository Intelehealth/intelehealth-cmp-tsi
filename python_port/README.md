# TSI DPDP CMS Python Port

FastAPI backend for this fork. Static UI lives in `../web`, JSON Schema validators in `../web/WEB-INF/validator`, and PostgreSQL schema in `../db`.

## Run

From the repository root, copy `.env.example` to `.env` and set secrets (`openssl rand -hex 32`). Then:

```bash
cd python_port
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn dpdpcms_py.main:app --host 127.0.0.1 --port 8080
```

On macOS/Linux: `source .venv/bin/activate`.

Required environment variables: `POSTGRES_HOST`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWD`, `JWT_SECRET`, `DB_ENCRYPTION_KEY`, `TSI_LOOKUP_SALT`, `BOOTSTRAP_TOKEN`. Optional: `ALLOWED_ORIGINS`, `BRAND_NAME`, `TSI_EXPORT_PATH`, `TSI_DPDP_CMS_ENV`.

`BOOTSTRAP_TOKEN` protects the Super-Admin bootstrap endpoint (`/api/v1/bootstrap/setup`). Present it as an `X-Bootstrap-Token` header (or `bootstrap_token` in the request body) to run the initial setup.

## Worker

Run the background worker as its own process (Compose exposes it as the `python_worker`
service). It performs the P1 sweeps: notification delivery (email/SMS/push), webhook
dispatch, time-bound purpose closure, alert/grievance escalation, the retention sweep,
and the queued-export job runner.

```bash
python -m dpdpcms_py.worker              # poll every WORKER_POLL_SECONDS
python -m dpdpcms_py.worker --once       # single sweep cycle (cron-style)
python -m dpdpcms_py.worker --poll 60    # override the poll interval
```

## P1 optional environment (worker & delivery)

| Variable | Role | Default |
| --- | --- | --- |
| `WORKER_POLL_SECONDS` | Seconds between worker sweep cycles | `30` |
| `WORKER_BATCH_SIZE` | Rows per sweep | `50` |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USERNAME` / `SMTP_PASSWORD` / `SMTP_FROM` / `SMTP_STARTTLS` | Email delivery channel (unset → email skipped, never silently "sent") | unset |
| `SMS_GATEWAY_URL` / `PUSH_GATEWAY_URL` | JSON POST gateways receiving `{"channel","recipient_id","message"}` | unset |
| `NOTIFICATION_RETRY_LIMIT` / `WEBHOOK_RETRY_LIMIT` | Delivery retries before FAILED | `5` |
| `ALERT_ESCALATION_HOURS` | Unacknowledged alert escalation window (NT-09) | `24` |
| `PURGE_NOTICE_HOURS` | Retention deletion notice window (DPDP Rule 8(2)) | `48` |
| `GRIEVANCE_ESCALATION_HOURS` | Grievance auto-escalation past SLA | `24` |

## Tests & lint

```bash
# From repository root, with the same env vars as CI (see root README.md).
ruff check python_port
cd python_port && pytest -q
```

Tests are unit-level only (no Postgres in CI): SSRF URL validation, webhook signing, purpose lifecycle validation, principal scoping helpers, TOTP, role permissions, retention floor rules.

## Notes

- API routing mirrors the original servlet filter: `/api/v1/admin/{service}`, `/api/v1/client/{service}`, `/api/v1/public/{service}`, `/api/v1/bootstrap/setup`, and legacy `/api/v1/{service}`.
- P1 endpoints: `/api/v1/admin/purpose` (`set_purpose_state`, `close_purpose`, `list_purpose_lifecycle`) and `/api/v1/client/alerts` (`notify_alert`, `acknowledge_alert`, `list_alerts`); policy authoring now requires a `duration_type` (`OPEN_ENDED`/`TIME_BOUND`) on every purpose, and `publish_policy` auto-notifies affected principals (`notify_policy_change`, `request_reconsent`).
- P2 endpoints: `/api/v1/admin/retention` (`create_retention_policy`, `update_retention_policy`, `get_retention_policy`, `list_retention_policies`, `delete_retention_policy`, `validate_completeness`) for the configured retention schedule that the worker's retention sweep now reads first (DD-03); `/api/v1/admin/role` (`create_role`, `set_role_permissions`, `list_roles`, `get_role`, `delete_role`) with the seeded `AUDITOR` role; `/api/v1/admin/operator` MFA (`enrol_mfa`, `verify_mfa`), with login issuing an `mfa_required` challenge and audit-log reads gated on role + MFA (LG-06); `/api/v1/client/consent` `export_consent_history` (CSV download of the principal's own history, UD-04); `/api/v1/client/grievance` `submit_grievance` now returns a `reference_number` and accepts `consent_record_id` (UD-10, GR-05, GR-14); `validate_consent` notifies the principal on denial (CV-07) and `withdraw_consent` verifies each purpose had active consent (CW-06); audit rows now carry `purpose_id`, `consent_status`, `initiator` and `source_ip` as discrete columns (LG-02/03).
- Encrypted PII columns use PostgreSQL `pgcrypto`, same as the Java implementation.
- Static HTML is served from `web/` with optional `BRAND_NAME` substitution.
