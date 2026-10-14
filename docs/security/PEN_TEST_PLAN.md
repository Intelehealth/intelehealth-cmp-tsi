# Authenticated penetration test plan (M-01)

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
