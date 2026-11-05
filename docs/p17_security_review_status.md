# P17 security review: remediation status

Status of the 15-point security review of the Python port (`python_port/`), as of 5 November 2026.
Item 5 (the principal OTP) was out of scope for this round. Item IDs `P17-nn` match the CHANGELOG.

Most items were already closed on `p16_changes` before this review. The review appears to have been
done against `main`, which is behind that branch.

## Summary

| # | Review item | Status |
|---|---|---|
| 1 | Take the tenant from the API key or token, not the request body | Already done |
| 2 | Accept only operator tokens on admin endpoints | **Fixed in P17** |
| 3 | Enforce roles on every admin function, from one central table that denies by default | Already done |
| 4 | Gate first-run setup with `TSI_BOOTSTRAP_TOKEN` | Gate already done; **variable renamed in P17** |
| 5 | Make the principal OTP real (random, single-use, short-lived, not returned, no `DUMMY_OTP` in production) | Out of scope for this round |
| 6 | Reject placeholder secrets outside local mode | **Fixed in P17** |
| 7 | Authenticate before validating payloads (CVE-2026-108810) | Already done |
| 8 | Port `LoginRateLimiter` to login, recovery and OTP endpoints | Login and recovery already done; **OTP fixed in P17** |
| 9 | Return a 401, not a 500, for a malformed API key | **Fixed in P17** |
| 10 | Port the `TokenBlocklist` so logout revokes the token | Already done |
| 11 | Serialise audit writes so the hash chain can't fork | Already done |
| 12 | Fail closed when a validator schema is missing | Already done |
| 13 | Check webhook URLs with the same SSRF guard as `WebhookDispatcher` | Already done |
| 14 | Stop serving `web/WEB-INF/` | Already done |
| 15 | Add the CSP header | Already done |

## Already done before this review

| # | Where |
|---|---|
| 1 | `python_port/dpdpcms_py/main.py` `authenticate()`: an API key, a principal token or a fiduciary-scoped operator overwrites any `fiduciary_id` in the body. Only a global ADMIN picks a tenant through the payload. |
| 3 | `python_port/dpdpcms_py/services/roles.py`: `FUNC_PERMISSIONS` and `SERVICE_RESOURCES` map each admin `(service, function)` to a permission. `enforce_role_permission` runs on every authenticated admin call. An unmapped service needs a permission no role holds, so only full access (`*`) reaches it. |
| 4 | `main.py` `_bootstrap_authorized`: `/api/v1/bootstrap/setup` needs the token in `X-Bootstrap-Token`, compared in constant time. |
| 7 | `main.py` `dispatch()`: `authenticate()` runs before `validate_payload()`, and validation also runs on GET. |
| 8 | `python_port/dpdpcms_py/throttle.py` (the `LoginRateLimiter` port) throttles operator `login` and `verify_recovery_key` by account and by IP, with escalating lockouts. |
| 10 | `main.py` `authenticate()` checks `revoked_tokens` (logout revokes one token) and `operators.tokens_valid_after` (deactivation or a password change revokes all of an account's tokens). |
| 11 | `python_port/dpdpcms_py/audit.py`: `log_event` takes `pg_advisory_xact_lock(AUDIT_CHAIN_LOCK)` before reading the chain head and inserting. |
| 12 | `python_port/dpdpcms_py/validators.py`: a function with no `.jschema` is rejected as "Unsupported function" and never dispatched unvalidated. |
| 13 | `python_port/dpdpcms_py/services/governance.py`: webhook URLs go through `netutil.validate_outbound_url` when saved, and again at dispatch. |
| 14 | `main.py` `static_or_index`: any path with a `WEB-INF` or `META-INF` segment returns 404, matched case-insensitively and with trailing dots stripped. |
| 15 | `main.py`: `CONTENT_SECURITY_POLICY` is sent on every response, along with HSTS, `X-Frame-Options`, `nosniff`, `Referrer-Policy` and COOP. |

## Fixed in P17

### P17-02: admin endpoints accept operator tokens only

Before, the admin API refused tokens with `typ=principal`, but operator tokens carried no `typ`. The rule
was "not a principal" rather than "is an operator".

- `security.token()` now stamps `typ=operator`. `principal_token()` still sets `typ=principal`.
- `main.authenticate()` calls `security.is_operator_token()` and returns 401 for any other type,
  before the operator lookup.
- Untyped tokens issued before this deploy are accepted until they expire (at most `token_ttl_minutes`,
  8 hours by default), so nobody is logged out. An untyped token minted after start-up is refused.

### P17-04: `TSI_BOOTSTRAP_TOKEN`

- `config.py` reads `TSI_BOOTSTRAP_TOKEN`, and falls back to `BOOTSTRAP_TOKEN` when it is unset, so
  existing `.env` files keep working.
- `docker-compose.yml`, `.env.example`, CI, `install-helper/02-secrets.sh`, `install-helper/bootstrap-admin.sh`,
  `README.md`, `docs/LOCAL_DEPLOYMENT.md` and `docs/security/KEY_MANAGEMENT.md` use the new name.
- Installer hosts that already have `BOOTSTRAP_TOKEN` keep it: `bootstrap-admin.sh` rotates whichever
  variable is in use.

### P17-06: placeholder secrets refused outside local mode

`docker-compose.yml` defaults `JWT_SECRET`, `DB_ENCRYPTION_KEY`, `TSI_LOOKUP_SALT`, the bootstrap token and
`POSTGRES_PASSWD` to published values. Those passed the old check, so a staging or production stack started
without its own `.env` came up with known keys.

- `config._secret()` now refuses, outside `TSI_DPDP_CMS_ENV=local`, any secret containing
  `do-not-use-in-production`, `secure_dev_password`, `local-dev-`, `placeholder` or `changeme`.
- `CERTIFICATE_SIGNING_KEY` goes through the same check when it is set.
- Local mode still accepts the defaults, so `docker compose up` works unchanged for development.

### P17-08: login throttle on the OTP endpoints

OTP had a per-principal request cap and a per-code attempt cap, but no per-IP limit. One IP could spray
guesses across many principals.

- `principal_login` counts each wrong OTP (including a wrong `DUMMY_OTP` code) against the principal
  (`otp:subject`, locked after 10) and the source IP (`otp:ip`, locked after 30).
- While either is locked, `principal_login` and `request_principal_otp` both return 429, so a locked
  caller cannot request fresh codes either.
- A successful login clears the principal's count only. The IP count is kept, so one successful login
  doesn't erase a record of guessing at other principals.
- The thresholds are `MAX_SUBJECT_FAILURES` and `MAX_IP_FAILURES` in
  `python_port/dpdpcms_py/principal_otp.py`.

### P17-09: malformed API key is a 401

`api_key_valid` passed the key id straight into `WHERE k.id = %s`. A non-UUID raised a Postgres `DataError`,
which was returned as 400 (and as 500 in earlier builds). Key ids are now parsed as UUIDs first, and a
malformed key is a 401 with no database query.

## Operator impact

- A staging or production stack that relies on the compose default secrets will refuse to start until
  real values are set. Generate them with `openssl rand -hex 32`.
- Rename `BOOTSTRAP_TOKEN` to `TSI_BOOTSTRAP_TOKEN` in `.env` when convenient. The old name keeps working.
- A clinic or carrier NAT that shares one IP among many principals could reach the 30-failure IP limit.
  Adjust `MAX_IP_FAILURES` if needed.

## Verification

- New tests: `python_port/tests/test_p17_remediation.py` (48 tests). The CHANGELOG test count is now 623.
- Unit suite, run without a database: no new failures against a clean HEAD. Two tests fail in both runs
  only because no database was reachable (`test_record_alert_failure_logs_no_row_detail`,
  `test_link_user_does_not_accept_age_or_verification`).
- Not yet run: the database-backed tests (`test_integration_db.py` and the other `needs_db` tests) and
  `pentest/`. Run both against Postgres before merging.
