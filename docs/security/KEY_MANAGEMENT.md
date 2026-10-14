# Key management (Rule 6(1)(a))

## Inventory

| Secret | Protects | Minimum | Rotatable? | Where it must live |
| --- | --- | --- | --- | --- |
| `DB_ENCRYPTION_KEY` | pgcrypto columns: principal and operator email and phone, MFA secrets, webhook secrets, queued OTPs. Also the default certificate signing key. | 32 chars | **No.** Every encrypted column must be re-encrypted first (see below). | A secrets manager, injected as an environment variable. Never in the image, the repo, or a backup. |
| `TSI_LOOKUP_SALT` | HMAC pseudonyms of principal ids in the audit ledger | 32 chars | **No.** Rotating it orphans every ledger pseudonym. | A secrets manager, kept apart from the database and its backups |
| `JWT_SECRET` | Operator and principal session tokens (HS256) | 32 chars | Yes. Rotating it signs everyone out. | A secrets manager |
| `BOOTSTRAP_TOKEN` | One-time super-admin bootstrap | 32 chars | Yes. Rotate, or unset it, once the first admin exists. | A secrets manager |
| `CERTIFICATE_SIGNING_KEY` | Evidence certificates (defaults to `DB_ENCRYPTION_KEY`) | – | Yes. Certificates signed with the old key then verify only against that key. | A secrets manager |
| `POSTGRES_PASSWD` | Database login | 8 chars | Yes | A secrets manager |

The process refuses to start if a secret is missing, too short, or still `change-me` (`config.py`).

## Generation

`openssl rand -hex 32` for each secret. Generate on the machine that will hold the secret, never on a laptop that syncs to the cloud. Use a different value in every environment.

## Segregation

- Backups (`backups/*.dump`) hold ciphertext and pseudonyms. Never store `DB_ENCRYPTION_KEY` or `TSI_LOOKUP_SALT` in the same place, or under the same access, as the backups.
- Only the application and worker processes read the keys. Operators never need them.

## Rotating `DB_ENCRYPTION_KEY`

The key cannot be swapped in place. The procedure is:

1. Take a backup and run `restore-test.sh`.
2. In one maintenance transaction, re-encrypt each column: `pgp_sym_encrypt(pgp_sym_decrypt(col, old), new)`.
3. Restart with the new key and run the smoke test.

Record each rotation below.

## Encryption at rest, and TLS

Neither is set in the repo:

- **Database volume and backups.** Use an encrypted volume (cloud disk encryption, or LUKS), and encrypted backup storage.
- **TLS.** Terminate TLS 1.2 or higher at the reverse proxy. Outside `TSI_DPDP_CMS_ENV=local` the application already requires TLS to Postgres (`sslmode=require`).

## Log

| Date | Secret | Action | By | Notes |
| --- | --- | --- | --- | --- |
| | | | | |
