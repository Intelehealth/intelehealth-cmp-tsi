# Key management (Rule 6(1)(a))

## Inventory

| Secret | Protects | Minimum | Rotatable? | Where it must live |
| --- | --- | --- | --- | --- |
| `DB_ENCRYPTION_KEY` | pgcrypto columns: every principal identifier (stored as `_enc` ciphertext), principal ids sealed inside alert and webhook payloads, guardian verification evidence, consent and audit IP addresses (audit IPs sit in append-only, hash-covered rows and can never be re-encrypted), principal and operator email and phone, MFA secrets, webhook secrets, queued OTPs. Also the default certificate signing key, the operator and fiduciary `email_hmac`, and - where `PII_LOOKUP_KEY` is unset outside production - the lookup key below. | 32 chars | **Not once data exists.** Every encrypted column must be re-encrypted first, and audit IPs stay tied to the old key (see below). | A secrets manager, injected as an environment variable. Never in the image, the repo, or a backup. |
| `PII_LOOKUP_KEY` | Every principal lookup HMAC: the `<col>_hmac` beside each `_enc` column, the `<key>_hmac` of sealed payload keys, and the `principal_id_hmac` new certificates sign (P16-04). Kept apart from `DB_ENCRYPTION_KEY` so one leaked secret does not give both decryption and linkability, and so either can change without the other. | 32 chars; must differ from `DB_ENCRYPTION_KEY` | Yes, with `python -m dpdpcms_py.rekey_lookup` (below). Certificates issued under an earlier lookup key fail live subject verification, as for `DB_ENCRYPTION_KEY`. | A secrets manager, apart from `DB_ENCRYPTION_KEY`. **Required with `TSI_DPDP_CMS_ENV=production`**; elsewhere it falls back to `DB_ENCRYPTION_KEY` when unset. |
| `TSI_LOOKUP_SALT` | HMAC pseudonyms of principal ids in the audit ledger | 32 chars | **No.** Rotating it orphans every ledger pseudonym. | A secrets manager, kept apart from the database and its backups |
| `JWT_SECRET` | Operator and principal session tokens (HS256) | 32 chars | Yes. Rotating it signs everyone out. | A secrets manager |
| `BOOTSTRAP_TOKEN` | One-time super-admin bootstrap | 32 chars | Yes. Rotate, or unset it, once the first admin exists. | A secrets manager |
| `CERTIFICATE_SIGNING_KEY` | Evidence certificates (defaults to `DB_ENCRYPTION_KEY`) | – | Yes. Certificates signed with the old key then verify only against that key. | A secrets manager |
| `POSTGRES_PASSWD` | Database login | 8 chars | Yes | A secrets manager |
| `HEALTHZ_TOKEN` | Health-endpoint detail for the monitor (optional) | 32 chars recommended | Yes | The monitoring system's secret store |

The process refuses to start if a secret is missing, too short, or still `change-me` (`config.py`).

## Generation

`openssl rand -hex 32` for each secret. Generate on the machine that will hold the secret, never on a laptop that syncs to the cloud. Use a different value in every environment.

## Segregation

- Backups (`backups/*.dump`) hold ciphertext and pseudonyms. Never store `DB_ENCRYPTION_KEY`, `PII_LOOKUP_KEY` or `TSI_LOOKUP_SALT` in the same place, or under the same access, as the backups.
- `DB_ENCRYPTION_KEY` and `PII_LOOKUP_KEY` are separate secrets with separate access where the secrets manager allows it.

## Setting or rotating `PII_LOOKUP_KEY`

A new deployment sets it before the first row is written; nothing else is needed. On a database that already holds data (lookups made under `DB_ENCRYPTION_KEY`, or under an earlier lookup key):

1. Take a backup and run `restore-test.sh`. Stop the API and the worker.
2. Set the new `PII_LOOKUP_KEY` in the environment and run `python -m dpdpcms_py.rekey_lookup` once. In one transaction it recomputes every `<col>_hmac` that has a `<col>_enc` beside it from the decrypted value (consent records under the maintenance opt-in; the `db/37` delivery floor accepts a re-keyed HMAC whose ciphertext is unchanged), and re-seals the principal keys in alert and webhook payloads. `operators.email_hmac` and `fiduciaries.email_hmac` are not principal lookups and stay on `DB_ENCRYPTION_KEY`.
3. Start the API and the worker and run the smoke test (a principal sign-in and a consent lookup).
4. Certificates record which key made their `principal_id_hmac`: those issued before `PII_LOOKUP_KEY` existed keep verifying against `DB_ENCRYPTION_KEY`; those issued under an earlier `PII_LOOKUP_KEY` fail live subject verification after a later rotation, so export them with a verification record first, as for `DB_ENCRYPTION_KEY`.
5. Record the change in the log below.
- Only the application and worker processes read the keys. Operators never need them.

## Rotating `DB_ENCRYPTION_KEY`

Do not rotate this key once the database holds data unless you accept the limits below. The key cannot be swapped in place, and three things cannot follow it to a new key:

- **Audit IP addresses.** `audit_logs.source_ip`, in the live table and in every `audit_logs_y<YYYY>_archive` table, is pgcrypto ciphertext inside append-only rows whose hash covers the stored ciphertext (`db/19`, `db/35`). It is never re-encrypted: the triggers refuse the UPDATE, and a rewrite would break the hash chain. After rotation, every audit IP written under the old key can be read only with the old key. Either keep the old key (in the secrets manager, read only by whoever must decrypt historic audit IPs) or accept that those IPs become unreadable. Note that the console audit reads decrypt `source_ip` with the current key through `tsi_audit_source_ip()`, which raises on a row it cannot decrypt rather than leak ciphertext, so after rotation `list_logs`, `get_log` and the access report fail on any range that includes pre-rotation rows with an IP. In practice this makes rotation unsupported once audit rows exist, until the application can decrypt with more than one key.
- **Evidence certificates.** A certificate issued before `PII_LOOKUP_KEY` was introduced signs `principal_id_hmac`, an HMAC keyed by `DB_ENCRYPTION_KEY` (newer ones are keyed by `PII_LOOKUP_KEY` and say so), and every certificate is signed with `DB_ENCRYPTION_KEY` unless `CERTIFICATE_SIGNING_KEY` is set. After rotation, `verify_certificate` recomputes the subject HMAC with the new key and returns `valid: false` with "The certificate's subject no longer matches its signed principal" for every certificate issued before the rotation (and "Signature mismatch" as well when the signing key was the default). Nothing was tampered with. Before rotating, set `CERTIFICATE_SIGNING_KEY` to the current key so signatures keep verifying, export the existing certificates with a verification record made under the old key, and tell verifiers that certificates issued before the rotation date must be checked against that record, not re-verified live. Certificates issued after rotation verify normally.
- **Consent records.** `consent_records` is append-only (`db/25`-`db/27`). Re-keying its `_enc`, `_hmac` and `ip_address_enc` columns is an UPDATE the triggers allow only inside a transaction that first called `db.allow_consent_maintenance(cur)` (`SELECT set_config('tsi.consent_maintenance', 'on', true)`).

If you still rotate, the procedure is:

1. Take a backup and run `restore-test.sh`.
2. In one maintenance transaction, re-encrypt each column: `pgp_sym_encrypt(pgp_sym_decrypt(col, old), new)`. Call `db.allow_consent_maintenance(cur)` first for `consent_records`, and skip `audit_logs.source_ip` and the archive tables (see above).
3. Principal lookup HMACs are keyed by `PII_LOOKUP_KEY` once it is set, so they do not change. A deployment still running without `PII_LOOKUP_KEY` should set it first (above); otherwise every `<col>_hmac` must be recomputed from the decrypted value with the new key in the same transaction.
4. Set `app.enc_key` to the new key (`ALTER DATABASE <db> SET app.enc_key = '<new key>'`), restart with the new key and run the smoke test.
5. Record the rotation date, and where the old key is kept, in the log below.

Principal identifiers depend on this key entirely. Since migration 34 no plaintext copy exists, so losing `DB_ENCRYPTION_KEY` loses who every consent, grievance, purge request and notification belongs to. Back it up separately from the database. Migration 34 refuses to run on a database that has rows when `app.enc_key` is unset; set it first (`ALTER DATABASE <db> SET app.enc_key = '<DB_ENCRYPTION_KEY>'`, then reconnect).

Record each rotation below.

## Encryption at rest, and TLS

Neither is set in the repo:

- **Database volume and backups.** Use an encrypted volume (cloud disk encryption, or LUKS), and encrypted backup storage.
- **TLS.** Terminate TLS 1.2 or higher at the reverse proxy. Outside `TSI_DPDP_CMS_ENV=local` the application already requires TLS to Postgres (`sslmode=require`).

## Log

| Date | Secret | Action | By | Notes |
| --- | --- | --- | --- | --- |
| | | | | |
