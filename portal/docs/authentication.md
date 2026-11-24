---
id: authentication
title: Authentication
---

# Authentication

The client API accepts two kinds of credential. Functions under `/api/v1/public/` need none.

| Credential | Sent as | Used by |
|---|---|---|
| Application API key | `X-API-Key` and `X-API-Secret` headers, together | A fiduciary's backend |
| Principal token | `Authorization: Bearer <token>` | An app the data principal has signed in to |

## API key

An API key belongs to one application of one fiduciary. Send both headers on every call:

```bash
curl -X POST https://cms.example.org/api/v1/client/policy/get_active_policy \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: 7b0c6f0e-...' \
  -H 'X-API-Secret: <secret>' \
  -d '{"fiduciary_id": "<your fiduciary id>"}'
```

A key carries **scopes**. Each function's reference page states the one it needs.

| Scope | Covers |
|---|---|
| READ | Reading policies, consent records, history, grievances, notifications |
| WRITE | Recording and withdrawing consent, erasure requests, grievances, nominations, corrections |
| PURGE | Confirming that a purge was carried out |

A missing or wrong key, and a key that lacks the required scope, both get **401**.

## Principal token

A data principal signs in with a one-time code. Two calls, neither needs a credential:

**1. Ask for a code.** The code is sent to the principal out of band and is never returned in the response.

```bash
curl -X POST https://cms.example.org/api/v1/public/principal/request_principal_otp \
  -H 'Content-Type: application/json' \
  -d '{"fiduciary_id": "<fiduciary id>", "user_id": "<principal identifier>"}'
```

**2. Exchange the code for a token.**

```bash
curl -X POST https://cms.example.org/api/v1/public/principal/principal_login \
  -H 'Content-Type: application/json' \
  -d '{"fiduciary_id": "<fiduciary id>", "user_id": "<principal identifier>", "otp": "<code>"}'
```

The response contains `token`. Send it as a bearer token on client API calls:

```bash
curl -X POST https://cms.example.org/api/v1/client/consent/list_consent_history \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{}'
```

A wrong or expired code gets **401**. Repeated failures lock the principal and the source address for a time, and both calls then answer **429**.

### What a principal token can do

- It acts for one principal of one fiduciary. See [Tenancy and identity](/tenancy).
- It is not accepted for functions that need the PURGE scope.

## GET or POST

Use POST. A function that only reads may also be called with GET, with its fields in the query string; the reference shows a GET variant where that works. A credential is never read from the query string.
