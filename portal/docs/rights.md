---
id: rights
title: Rights requests
---

# Rights requests

The functions a principal-facing app uses to exercise a principal's rights. Examples assume a principal token (`Authorization: Bearer <token>`), so `user_id` is taken from the token; with an API key, send `user_id` in the body. See [Tenancy and identity](/tenancy).

## Access: see and download consent history

```bash
curl -X POST https://cms.example.org/api/v1/client/consent/list_consent_history \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer <token>' \
  -d '{"page": 1, "limit": 20}'
```

For a file the principal can keep, [`export_consent_history`](/integrator-api/client-consent-export-consent-history) returns CSV text, or a PDF with `"format": "pdf"`.

## Erasure

Ask for personal data to be erased, for some purposes or all. Scope: WRITE.

```bash
curl -X POST https://cms.example.org/api/v1/client/consent/erasure_request \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer <token>' \
  -d '{"purpose_ids": ["marketing"], "reason": "Account closed"}'
```

Reference: [`erasure_request`](/integrator-api/client-consent-erasure-request).

The fiduciary's processors then carry out the purge and report back with [`list_purge_requests`](/integrator-api/client-compliance-list-purge-requests), [`update_purge_status`](/integrator-api/client-compliance-update-purge-status) and [`confirm_purge_status`](/integrator-api/client-compliance-confirm-purge-status). Confirming needs an API key with the PURGE scope; a principal token is not accepted.

## Correction

Ask for a stored value to be corrected. Scope: WRITE. Required: `field_name` and `requested_value`.

```bash
curl -X POST https://cms.example.org/api/v1/client/rights/submit_correction \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer <token>' \
  -d '{"field_name": "phone", "current_value": "98xxxxxx10", "requested_value": "98xxxxxx11", "reason": "Number changed"}'
```

Track requests with [`list_corrections`](/integrator-api/client-rights-list-corrections).

## Nomination

Name another person to exercise the principal's rights. Scope: WRITE. Required: `nominating_principal_id` and `nominated_principal_id`.

```bash
curl -X POST https://cms.example.org/api/v1/client/rights/create_nomination \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer <token>' \
  -d '{"nominating_principal_id": "<principal identifier>", "nominated_principal_id": "<nominee identifier>", "relationship": "spouse"}'
```

List with [`list_nominations`](/integrator-api/client-rights-list-nominations); cancel with [`revoke_nomination`](/integrator-api/client-rights-revoke-nomination) and its `nomination_id`.

## Notifications

The CMS records a notification for the principal when something changes. Read them with [`list_notifications`](/integrator-api/client-notification-list-notifications) and mark one read with [`mark_notification_read`](/integrator-api/client-notification-mark-notification-read).
