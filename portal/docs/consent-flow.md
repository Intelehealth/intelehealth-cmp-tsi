---
id: consent-flow
title: Record and check consent
---

# Record and check consent

The usual flow for a fiduciary application, using an API key. Examples leave out the two key headers; see [Authentication](/authentication).

## 1. Fetch the policy to show

The policy holds the purposes the principal is asked to agree to. Scope: READ.

```bash
curl -X POST https://cms.example.org/api/v1/client/policy/get_active_policy \
  -H 'Content-Type: application/json' \
  -d '{"fiduciary_id": "<fiduciary id>"}'
```

Show each purpose to the principal and collect a separate yes or no for each. Reference: [`get_active_policy`](/integrator-api/client-policy-get-active-policy).

## 2. Record the decision

Scope: WRITE. Required fields are `user_id`, `policy_id` and `data_point_consents`, one entry per purpose.

```bash
curl -X POST https://cms.example.org/api/v1/client/consent/record_consent \
  -H 'Content-Type: application/json' \
  -d '{
    "user_id": "<principal identifier>",
    "policy_id": "<policy id from step 1>",
    "language_selected": "en",
    "data_point_consents": [
      {
        "data_point_id": "care",
        "consent_granted": true,
        "purpose_agreed_to": "Providing care",
        "timestamp_updated": "2026-11-24T09:15:00Z"
      },
      {
        "data_point_id": "marketing",
        "consent_granted": false,
        "purpose_agreed_to": "Marketing messages",
        "timestamp_updated": "2026-11-24T09:15:00Z"
      }
    ]
  }'
```

- Each entry needs four fields: `data_point_id` (the purpose), `consent_granted` (the decision), `purpose_agreed_to` (the purpose as it was shown to the principal) and `timestamp_updated` (when they decided).
- Purpose ids are compared without regard to case.
- No other key is accepted. A consent has no caller-set expiry; an extra key is refused with 400.
- `language_selected` is `en` or one of the 22 Eighth Schedule language codes (`hi`, `bn`, `ta`…). Tags such as `en-IN` are refused.

A successful call answers 201. Reference: [`record_consent`](/integrator-api/client-consent-record-consent).

For a child, a guardian verification is recorded with [`record_parent_consent`](/integrator-api/client-consent-record-parent-consent).

## 3. Check before you process

Before using personal data for a purpose, ask whether consent stands. Scope: READ.

```bash
curl -X POST https://cms.example.org/api/v1/client/consent/validate_consent \
  -H 'Content-Type: application/json' \
  -d '{"user_id": "<principal identifier>", "required_purpose_id": "marketing"}'
```

Each check is logged, and a refusal notifies the principal, so this function is POST only even though it reads. Reference: [`validate_consent`](/integrator-api/client-consent-validate-consent).

## 4. Withdrawal

A principal may withdraw at any time. Scope: WRITE.

```bash
curl -X POST https://cms.example.org/api/v1/client/consent/withdraw_consent \
  -H 'Content-Type: application/json' \
  -d '{"user_id": "<principal identifier>", "purpose_ids": ["marketing"], "reason": "No longer wanted"}'
```

Leave `purpose_ids` out to withdraw every purpose. To show the principal what a withdrawal will mean before they confirm, call [`get_withdrawal_implications`](/integrator-api/client-consent-get-withdrawal-implications).

## Reading consent back

| Need | Function |
|---|---|
| The current consent for a principal | [`get_active_consent`](/integrator-api/client-consent-get-active-consent) |
| Every decision over time | [`list_consent_history`](/integrator-api/client-consent-list-consent-history) |
| One record in full | [`get_consent_record_details`](/integrator-api/client-consent-get-consent-record-details) |
| A CSV or PDF for the principal | [`export_consent_history`](/integrator-api/client-consent-export-consent-history) |
