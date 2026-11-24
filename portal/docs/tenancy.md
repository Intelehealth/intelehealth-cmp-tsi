---
id: tenancy
title: Tenancy and identity
---

# Tenancy and identity

The CMS serves many fiduciaries from one deployment. Two fields decide whose data a call touches, and on the client API the server takes both from your credential, not from your request.

## `fiduciary_id`

| You call with | `fiduciary_id` used |
|---|---|
| An API key | The fiduciary the key belongs to. A value in the body is overridden. |
| A principal token | The fiduciary the principal signed in to. A value in the body is overridden. |
| No credential (`/api/v1/public/`) | The value in the body. |

So a key or token can never read or write another fiduciary's records, whatever the body says. Many schemas still list `fiduciary_id`; on the client API you may leave it out.

## `user_id`

`user_id` identifies the data principal.

| You call with | `user_id` used |
|---|---|
| An API key | The value in the body. A key acts for its fiduciary and may name any of that fiduciary's principals. |
| A principal token | The principal in the token. You may leave `user_id` out. A `user_id` in the body that does not match the token is refused with **403**. |

With a principal token, lists are filtered to that principal, and a record that belongs to someone else answers **404**, the same as a record that does not exist.

## Function name in the path or the body

The function is normally the last path segment. It may instead be sent as `_func` in the body to `/api/v1/{category}/{service}`. If both are present, `_func` in the body is the one that runs.
