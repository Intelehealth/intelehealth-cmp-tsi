# Outbound destinations (Rule 14)

Every place the CMS sends personal data, or a principal identifier, outside its own database. When `OUTBOUND_ALLOWED_HOSTS` is set, any destination not listed there is refused:

- **webhooks**, at save time and at dispatch;
- **SMS, push and verifier calls**, at dispatch;
- **email**, at send.

| Destination | Configured by | Carries | Host | Hosting region | Approved by / date |
| --- | --- | --- | --- | --- | --- |
| Fiduciary webhooks (`webhook_configs`) | DPO console | Consent, withdrawal and erasure events with `user_id` | per fiduciary | | |
| Processor webhooks (`processor_webhook_configs`) | DPO console | The same, per processor | per processor | | |
| SMS gateway | `SMS_GATEWAY_URL` | Principal notices | | | |
| Push gateway | `PUSH_GATEWAY_URL` | Principal notices | | | |
| SMTP relay | `SMTP_HOST` | Staff notices | | | |
| DigiLocker verifier | `DIGILOCKER_VERIFY_URL` | Guardian verification reference | | | |
| SSO identity provider | `SSO_ISSUER`, `SSO_JWKS_URL` | Operator sign-in (no principal data) | | | |
| Sarvam TTS (tour page only) | `web/tour/voice-based-consent.html` | Demo text; no principal data | api.sarvam.ai | India | |
| Browser CDNs | `cdn.tailwindcss.com`, `cdnjs.cloudflare.com` | No personal data; the browser loads scripts | | | |

Process:

1. Fill in the host and the hosting region of each destination.
2. Put the approved hosts in `OUTBOUND_ALLOWED_HOSTS`.
3. Add a row here before configuring any new integration.

The database, backups and logs must also be hosted in India. Record their region in [BACKUP_AND_CONTINUITY.md](BACKUP_AND_CONTINUITY.md).
