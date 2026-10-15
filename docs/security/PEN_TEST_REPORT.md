# Pen-test report

## Run 1 - automated suite, 15 Oct 2026

**Target.** Local: the application in-process over its HTTP interface, on
Postgres 16 with `db/01..29`, branch `p11_changes` plus the workbook v10
remediation. Two tenants, provisioned through the API.

**Result.** 114 attacks. All 112 that run locally are refused. The other 2 are
remote-only checks (`/docs` hidden; HTTP redirects to HTTPS).

| Area | Attacks | Refused |
| --- | --- | --- |
| Authentication and session | 10 | 10 |
| Authorisation (cross-tenant, escalation, scopes) | 23 | 23 |
| Injection | 31 | 31 |
| Business logic | 9 | 9 |
| SSRF | 26 | 26 |
| Transport | 11 (+2 remote) | 11 |
| Brute force | 2 | 2 |

### Findings (fixed in the same change)

| Ref | Severity | Finding | Fix |
| --- | --- | --- | --- |
| PT-01 | Low | A malformed id (for example `get_breach` with `id: "not-a-uuid"`), an over-long value or a bad date reached SQL and returned **500**. There was no data exposure: the generic 500 body hides the database message. But it was an unhandled path, and it adds noise to monitoring. | The dispatcher maps every `psycopg.errors.DataError` to 400 with a generic message. Tests: `tests/test_pentest_findings.py`. |
| PT-03 | Low | A malformed JSON body (`{not json`) fell through to form parsing. Without `python-multipart` (not a dependency: CI and the Docker image) that raised and returned **500**. Found by the suite's first CI run. Locally it had passed, because the package happened to be installed. | `payload_from` parses a form only for a form Content-Type. Invalid JSON, or a form that cannot be parsed, is 400. Tests: `tests/test_pentest_findings.py`, which emulates the missing package. |
| PT-02 | Medium | **CSV formula injection.** `record_consent` accepted any `language_selected`, and the principal's consent-history CSV echoed it unneutralised. A value such as `-2+3` (the column holds five characters) became a live formula when the principal opened their own export. Longer payloads failed with a 500 (see PT-01). | `language_selected` must be `en` or an Eighth Schedule code (400 otherwise). The consent-history and ROPA CSVs, and every job export except AUDIT, prefix formula-leading cells with `'`. The AUDIT export stays byte-exact so its row hashes recompute: open it as text data, never as a live spreadsheet. |

### Not covered by this run

- **External test.** The authenticated test of a deployed staging instance,
  behind its real proxy and TLS, described in
  [PEN_TEST_PLAN.md](PEN_TEST_PLAN.md#external-test). The same suite can be
  pointed at that instance (`PENTEST_BASE_URL`) as a first pass.
- Denial of service, and races at scale.
- **The browser itself.** CSP compliance of all 31 pages was checked
  separately in headless Chrome: no violations. Stored-XSS rendering was not
  exercised in a browser.

## Log

| Date | Kind | Target | Tester | Result | Report |
| --- | --- | --- | --- | --- | --- |
| 15 Oct 2026 | Automated suite | Local, `p11_changes` + v10 remediation | Automated (`python_port/pentest/`) | 2 findings, both fixed; 112/112 refused | This page |
| 15 Oct 2026 | Automated suite | CI (GitHub Actions), `p12_changes` | Automated | 1 finding (PT-03), fixed; 112/112 refused after the fix | This page |
| 15 Oct 2026 | Automated suite | Local, `p12_changes` + v11 remediation | Automated | Added the same-id cross-tenant policy case (P13-01, a global ADMIN acting on every tenant's copy of a policy id); it failed on the old code and is refused after the fix. 113/113 refused, 2 remote-only skipped | This page |
| | External authenticated test | Staging | | | |
