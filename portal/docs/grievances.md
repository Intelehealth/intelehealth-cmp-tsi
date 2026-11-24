---
id: grievances
title: Grievances
---

# Grievances

A principal can raise a complaint or a request with the fiduciary and follow it to resolution. All functions are under `/api/v1/client/grievance/`.

## Submit

Scope: WRITE. Required: `user_id` (taken from a principal token), `type`, `subject`, `description`.

```bash
curl -X POST https://cms.example.org/api/v1/client/grievance/submit_grievance \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer <token>' \
  -d '{
    "type": "CONSENT_COMPLAINT",
    "subject": "Marketing messages after withdrawal",
    "description": "I withdrew marketing consent on 2 November and still receive messages.",
    "channel": "PORTAL"
  }'
```

`type` is one of:

| Value | Use for |
|---|---|
| `GENERAL_COMPLAINT` | Anything not covered below |
| `CONSENT_COMPLAINT` | How consent was taken or honoured |
| `DATA_HANDLING_COMPLAINT` | How personal data was used or shared |
| `DATA_ACCESS_REQUEST` | A request to see personal data |
| `CORRECTION_REQUEST` | A request to correct personal data |
| `ERASURE_REQUEST` | A request to erase personal data |

`channel` records how the grievance arrived: `PORTAL`, `EMAIL`, `PHONE`, `LETTER`, `IN_PERSON` or `OTHER`.

Reference: [`submit_grievance`](/integrator-api/client-grievance-submit-grievance).

## Follow

| Need | Function |
|---|---|
| One grievance, by `grievance_id` or by the `reference_number` quoted to the principal | [`get_grievance`](/integrator-api/client-grievance-get-grievance) |
| All of a principal's grievances | [`list_user_grievances`](/integrator-api/client-grievance-list-user-grievances) |

## Add to a grievance

Add a message without changing the grievance's status. Required: `grievance_id`, `message`.

```bash
curl -X POST https://cms.example.org/api/v1/client/grievance/add_grievance_communication \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer <token>' \
  -d '{"grievance_id": "<grievance id>", "message": "Attaching the message I received on 10 November."}'
```

Attach evidence with [`upload_grievance_attachment`](/integrator-api/client-grievance-upload-grievance-attachment). The file travels base64-encoded in the JSON body as `content_base64`, with `file_name` and `content_type`. Accepted types: `application/pdf`, `image/png`, `image/jpeg`, `text/plain`. A file over the size limit answers 413. Read one back with [`get_grievance_attachment`](/integrator-api/client-grievance-get-grievance-attachment).

## Rate the outcome

Once a grievance is resolved, the principal can rate how it was handled. Required: `grievance_id`, `rating` (a whole number from 1 to 5); `comment` is optional.

Reference: [`submit_grievance_feedback`](/integrator-api/client-grievance-submit-grievance-feedback).
