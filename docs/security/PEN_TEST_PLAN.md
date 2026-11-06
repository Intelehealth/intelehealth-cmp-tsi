# Authenticated penetration test plan (M-01)

## Automated pen test (in the repository)

`python_port/pentest/` is an automated, authenticated attack suite. It covers
every in-scope area below except denial of service and social engineering.

**How it works**

- It goes through the real HTTP interface: routing, authentication, roles and
  scopes, schema validation, and the services, against a real Postgres.
- It provisions two tenants through the API. Each tenant gets a DPO, an
  OPERATOR, an AUDITOR, a processor app with READ/WRITE, READ and PURGE keys,
  an active policy (both tenants use the same policy id), consents, a
  grievance, a breach, a purge request and a principal session.
- It then uses tenant A's credentials against tenant B.
- Every test is an attack that must fail. A failing test is a finding.

**What it attacks**

| Area | File | Attacks |
| --- | --- | --- |
| Authentication, session | `test_authentication.py` | Missing, garbage, guessed-key, `alg: none`, expired and role-inflated tokens; principal token on admin routes; logout replay; sessions of a deactivated operator; MFA skip, re-enrolment and code guessing; bootstrap re-run; recovery endpoint |
| Authorisation | `test_authorization.py` | Cross-tenant reads and writes by id (breach, grievance, purge, app, key, operator, consent record); tenant listings; shared policy ids; creating accounts above one's own role; custom-role escalation; read-only roles writing; platform-admin functions; API-key scopes, including the wallet action; API key on the admin API; wrong secret; key of a deactivated app; principal naming another principal or tenant; principal on PURGE functions |
| Injection | `test_injection.py` | SQL injection in every search and filter; JSON type confusion; malformed and over-long ids; `_func` dispatch escape; non-JSON and 2 MB bodies; static-route traversal to `WEB-INF`, source and `.env`; CSV formula injection in the consent export |
| Business logic | `test_business_logic.py` | Caller-set consent expiry; bundled, duplicate, non-boolean, undeclared and two-purpose decisions; consent on a superseded notice; granting a closed purpose; empty withdrawal; erasure for a stranger; purge completion without evidence or by the requesting app; future detection and out-of-range Board intimation; re-consent expiry smuggling |
| SSRF | `test_ssrf.py` | 25 internal or forbidden webhook targets: loopback, link-local metadata, RFC 1918, IPv6, IPv4-mapped, NAT64, decimal, hex and octal IPs, userinfo, DNS-to-loopback, and `file`/`gopher`/`ftp`/`dict`/`javascript` schemes |
| Transport | `test_transport.py` | CSP and the other security headers on pages and API responses; no cookies; CORS with an untrusted origin; writes over GET; credentials in the query string; other HTTP methods; health detail; leaked internals in errors; `/docs` hidden (remote); HTTP-to-HTTPS (remote) |
| Identifier reveal | `test_pii_reveal.py` | `reveal_user_id` by OPERATOR and AUDITOR; by a DPO on another tenant's record, naming either tenant; by API key, principal token and no credential; over GET; 21 reveals in a minute (P16-05) |
| Brute force | `test_zz_lockout.py` | Password spray and recovery-passphrase guessing are throttled (runs last) |

**Running it**

- Locally, or in CI, from `python_port/` after `db/*.sql` is applied:
  `python -m pytest -q pentest`. CI runs it on every push and keeps
  `pentest-report.xml`.
- Against staging, run the same command with these set: `PENTEST_BASE_URL`
  (https), `PENTEST_ADMIN_IDENTIFIER`, `PENTEST_ADMIN_PASSWORD`, and
  `PENTEST_ADMIN_TOTP_SECRET` if the account has MFA.
- The suite creates data on the target. Never run it against production.
  The brute-force file locks the client IP out of sign-in for 15 minutes, so
  against a remote target it runs only with `PENTEST_LOCKOUT=1`.

**What it does not replace.** The external test below is still required. The
suite only knows the attacks it was written with. It cannot test the
deployed proxy's TLS configuration, timing races at scale, or anything a
skilled tester would think of next. Results are recorded in
[PEN_TEST_REPORT.md](PEN_TEST_REPORT.md).

## External test

The security review read the source and ran individual functions against a live Postgres. It never drove requests through the deployed stack. This plan scopes the test that would.

**Target.** A staging deployment built from the release candidate:

- all `db/*.sql` applied;
- the worker running;
- the reverse proxy and TLS configured as in production;
- two tenants.

**Accounts.**

- One ADMIN; and per tenant a DPO, an OPERATOR and an AUDITOR.
- READ and WRITE API keys for each tenant, plus one processor key.
- Two principals per tenant.

## In scope

| Area | Tests |
| --- | --- |
| Authentication | OTP brute force and throttling; MFA bypass; token replay after logout; SSO nonce reuse; bootstrap token reuse |
| Authorisation | Cross-tenant access by id on every `_func` (IDOR); role escalation, including custom roles; principal-token use on admin routes; processor key reaching another processor's alerts |
| Injection | SQL, JSON-path, header and template injection; stored XSS in the console and the rights portal; CSV and XLSX formula injection in exports |
| Business logic | Consent on a superseded policy version; granting a closed purpose; withdrawal and erasure races; purge confirmation under a legal hold; re-consent flows |
| SSRF | Webhook and gateway URLs: DNS rebinding, redirects, IPv6 and embedded IPv4, and `OUTBOUND_ALLOWED_HOSTS` bypass |
| Transport | TLS versions and ciphers, HSTS, CSP effectiveness, CORS with an untrusted origin |
| Session | Fixation, concurrent sessions, token lifetime |

**Out of scope.** Denial of service and social engineering.

**Deliverable.** A findings report ranked by severity, a re-test of the fixes, and the report filed with the [control map](ISMS_CONTROL_MAP.md).

**Cadence.** Before go-live, after any release that changes authentication or tenancy, and at least once a year.
