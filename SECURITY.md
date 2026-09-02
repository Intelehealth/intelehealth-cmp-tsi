# Security Policy

This project handles consent records and encrypted personally identifiable information (PII) under India's DPDP Act context. We take security reports seriously and appreciate responsible disclosure.

## Supported versions

| Version | Supported |
| --- | --- |
| `main` (latest) | ✅ |
| Anything older | ❌ |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Report privately using one of these channels:

1. **GitHub private vulnerability reporting** — use the "Report a vulnerability" button under the repository's **Security** tab (preferred).
2. **Email** — support@intelehealth.org <!-- TODO: confirm/replace with your dedicated security contact, e.g. security@intelehealth.org -->

Include as much of the following as you can:

- A description of the vulnerability and its impact
- Steps to reproduce (a proof of concept helps)
- Affected component (`python_port/`, `web/`, `db/`, Docker/Compose configuration)
- Any suggested remediation

## What to expect

- **Acknowledgement** within 5 business days.
- **Initial assessment** within 14 days, including severity and an expected fix timeline.
- We will keep you informed of progress and credit you in the fix notes unless you prefer to remain anonymous.
- Please give us a reasonable window to remediate before any public disclosure (we suggest 90 days).

## Scope

In scope:

- Authentication/authorization flaws in the FastAPI application (JWT handling, API key scopes, bootstrap setup)
- PII exposure, encryption weaknesses (`pgcrypto` usage, `DB_ENCRYPTION_KEY` handling)
- Injection issues (SQL, template, header) in the app or DB init scripts
- Vulnerabilities in the static consoles under `web/` that affect real deployments

Out of scope:

- Issues that require the documented **local-development-only** Compose defaults (e.g., `do-not-use-in-production` secrets) in a production setting — these are explicitly unsupported configurations
- Denial of service via volumetric traffic
- Reports from automated scanners with no demonstrated impact
- Vulnerabilities in third-party dependencies with no exploitable path in this project (please report upstream, but a heads-up is welcome)

## Hardening guidance for deployers

- Never deploy with the Compose default secrets; set unique values via `.env`.
- Keep `TSI_DPDP_CMS_ENV` off `local` in deployed environments so `/docs` is disabled.
- Do not rotate `DB_ENCRYPTION_KEY` after data exists — plan key management before go-live.
- Keep Postgres bound to loopback or a private network; never expose `5432/5434` publicly.
