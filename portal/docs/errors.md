---
id: errors
title: Errors
---

# Errors

Every error response has the same JSON body:

```json
{
  "timestamp": "2026-11-24T09:15:02.118+00:00",
  "status": 400,
  "error": "Bad Request",
  "message": "'user_id' is a required property",
  "path": "/api/v1/client/consent/record_consent"
}
```

`message` is written for a developer. Do not show it to an end user unchanged.

## Status codes

| Status | Meaning | Usual cause |
|---|---|---|
| 400 | Bad Request | The body failed the function's schema, the function name is unknown, or a value is malformed or too long. `message` lists each problem. |
| 401 | Unauthorized | No credential, a wrong or inactive API key, a key without the required scope, a wrong one-time code, or a revoked token. |
| 403 | Forbidden | The function is not allowed for this kind of caller, or `user_id` does not match the principal token. |
| 404 | Not Found | The record does not exist, or belongs to another principal or fiduciary. |
| 405 | Method Not Allowed | GET was used for a function that is not a read. |
| 409 | Conflict | A record with these identifiers already exists. |
| 429 | Too Many Requests | The sign-in throttle is active after repeated failures. |
| 500 | Internal Server Error | An unexpected failure. The body carries no detail; the server log does. |

Attachment functions can also answer **413** (file too large) and **410** (the stored file is no longer available).

## Success

A successful call answers **200**, or **201** for functions that create a record (names starting `create_`, `generate_`, `record_`, `report_` or `submit_`). The body is JSON, except the export and download functions, which return CSV text or a PDF.

Response bodies are not yet specified field by field in the reference.
