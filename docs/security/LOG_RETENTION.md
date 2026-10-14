# Log and personal-data retention floor (Rule 6(1)(e))

Rule 6(1)(e) requires logs, and the personal data processed, to be kept for at least one year unless another law requires otherwise. The database enforces that floor, so it holds even against a caller with the application's credentials.

| Table | What it holds | Floor | Enforced by |
| --- | --- | --- | --- |
| `audit_logs` | The hash-chained access and processing ledger | Permanent: UPDATE, DELETE and TRUNCATE all fail | `db/19_audit_ledger_integrity.sql` |
| `notification_deliveries` | Every delivery attempt to a principal | No DELETE or TRUNCATE within 365 days; personal-data columns cannot be rewritten except by erasure | `db/23`, `db/24` |
| `webhook_deliveries` | Every event pushed to a fiduciary or processor | As above; within the floor, only erasure may re-key `user_id` | `db/23`, `db/24`, `db/26` |
| `notifications` | Notices raised to principals and staff | No DELETE within 365 days | `db/24` |
| `consent_records` | Consent artefacts | Append-only: no DELETE; UPDATE only for sanctioned maintenance | `db/25`, `db/26`, `db/27` |

The prune jobs (`prune_old_webhook_deliveries`, `prune_old_notification_deliveries`) default to 365 days (`WEBHOOK_DELIVERY_RETENTION_DAYS`, `NOTIFICATION_DELIVERY_RETENTION_DAYS`). A shorter setting is refused by the triggers above. The only things pruned earlier are expired revoked-token ids and SSO nonces. Neither is a log of access to personal data.

Erasure (s.12(3)) and the floor are reconciled by re-keying, not deleting. `erase_cms_copy` replaces the identifier with a random token in every table. The rows stay countable for the floor, but they no longer name anyone.
