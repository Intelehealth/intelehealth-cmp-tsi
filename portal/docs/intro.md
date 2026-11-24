---
id: intro
slug: /
title: Get started
sidebar_position: 1
---

# Get started

The TSI DPDP Consent Management System (CMS) records, validates and withdraws consent on behalf of a data fiduciary, and handles the rights a data principal has under the Digital Personal Data Protection Act: access, correction, erasure, nomination and grievance.

This portal has three sections.

| Section | What it is | Who it is for |
|---|---|---|
| **Docs** (this section) | Short guides to the concepts and the common flows | Anyone starting an integration |
| **[Integrator API](/integrator-api/tsi-dpdp-cms-api)** | Reference for every function under `/api/v1/client/` and `/api/v1/public/` | Fiduciary applications and principal-facing apps |
| **[Internal API](/internal-api/tsi-dpdp-cms-api-internal)** | Reference for every function, including the admin console API and its permissions | Developers working on the CMS itself |

:::note[Draft guides]
The API reference pages are generated from the server's own validation schemas and permission tables, so they match the running code. The guides in this section are hand-written and are still drafts; where a guide and the reference disagree, the reference is right.
:::

## How a call looks

Every function is one HTTP call:

```
POST https://<your-cms-host>/api/v1/{category}/{service}/{function}
Content-Type: application/json
```

- `category` is `client` (needs a credential) or `public` (no credential).
- `service` groups related functions: `consent`, `policy`, `grievance`, `principal` and so on.
- The body is a JSON object. Each function's reference page lists its fields.

A first call that needs no credential, listing the fiduciaries a principal can sign in to:

```bash
curl -X POST https://cms.example.org/api/v1/public/principal/list_active_fiduciaries \
  -H 'Content-Type: application/json' \
  -d '{}'
```

## Choose your integration

**You are building a fiduciary application** (a backend that collects and checks consent).
Use an application API key. Read [Authentication](/authentication), then follow [Record and check consent](/consent-flow).

**You are building a principal-facing app** (a rights portal or wallet, where the person signs in).
Use a principal token obtained with a one-time code. Read [Authentication](/authentication), then [Rights requests](/rights) and [Grievances](/grievances).

## Before you write code

1. Ask the CMS administrator for the host name, your `fiduciary_id`, and an API key and secret with the scopes you need (READ, WRITE, PURGE).
2. Read [Tenancy and identity](/tenancy). It explains which fields the server fills in from your credential.
3. Read [Errors](/errors). Every error has the same shape.

## The OpenAPI files

The reference is built from two OpenAPI 3.0.3 files in the repository, which you can import into Postman or a client generator:

- [`openapi-public.json`](https://github.com/Intelehealth/intelehealth-cmp-tsi/blob/main/docs/api/openapi-public.json)
- [`openapi-internal.json`](https://github.com/Intelehealth/intelehealth-cmp-tsi/blob/main/docs/api/openapi-internal.json)
