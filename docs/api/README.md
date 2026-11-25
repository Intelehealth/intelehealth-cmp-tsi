# API reference (OpenAPI)

Two OpenAPI 3.0.3 documents describe the Python port's API. Both are generated from the code; do not edit them by hand.

| File | Covers | For |
|---|---|---|
| `openapi-public.json` | `/api/v1/client/` and `/api/v1/public/` | Fiduciary integrators. This is the only file meant to be shared outside the team. |
| `openapi-internal.json` | Everything: `admin`, `bootstrap`, `client`, `public`, with the role permission each admin function needs | Developers working on the CMS. |

## Regenerate

```bash
cd python_port
python -m dpdpcms_py.openapi_gen          # rewrite both files
python -m dpdpcms_py.openapi_gen --check  # exit 1 if either is stale
```

Regenerate after adding, removing or renaming a service function, changing a validator schema in `web/WEB-INF/validator/`, or changing an allow-list, scope or permission. `python_port/tests/test_openapi_docs.py` fails when the committed files no longer match the code, so CI catches a missed regeneration.

## View

- Import either JSON file into any OpenAPI viewer (Swagger UI, Swagger Editor, Redoc, Postman).
- Or run the app with `TSI_DPDP_CMS_ENV=local` and load `/openapi.json` into a viewer; it is the internal spec. The app's own `/docs` page does not render yet: the Content-Security-Policy header blocks the Swagger UI scripts it loads from a CDN.

## What the documents contain

- One operation per function: `POST /api/v1/{category}/{service}/{func}`, plus `GET` where the function is a read.
- Request bodies are the validator schemas the server enforces at runtime, converted to the OpenAPI 3.0 subset. A conditional rule (`if`/`then`) cannot be expressed in OpenAPI 3.0; it is kept as text under `x-conditional-rule` and is still enforced by the server.
- The credential each operation accepts, and under `x-required-scope` / `x-required-permission` the API key scope or role permission it needs.
- The BRD module each operation belongs to, under `x-module`. `x-modules` at the top lists the modules that have operations in the document (name, BRD title, the services each owns), BRD modules first and in the BRD's order, then the extensions. Both come from the packages' `manifest.py`. Tags are still the service names.
- One shared error body for every error status.
- Descriptions come from the code's docstrings. A function without one has no description.

## What they do not contain

- Response bodies. Success responses are documented as a free-form JSON object (or as text or PDF for the export and download functions); per-function response schemas are not specified yet.
- Every status a function can return. 400, 401, 403, 404, 405, 409, 429 and 500 are declared on every operation; a few functions also answer 410 or 413.
- The legacy routes as separate operations. `/api/v1/{category}/{service}` with `_func` in the body is the same call and is described once in each document's introduction.

`x-unrouted` in the internal document lists validator schemas that no service implements, and allowed functions that have no schema.

## Production

A production deployment does not publish a spec or Swagger UI, by design. These files are the way to share the reference.

- Outside the local environment the app turns `/docs` and `/redoc` off, and nothing in this change alters that.
- nginx answers 404 for `/docs`, `/redoc` and `/openapi.json`. That block is what keeps `/openapi.json` off the network: the app itself still answers it on its own port. Outside local that is FastAPI's derived schema (the three catch-all routes, no function detail).
- `TSI_DPDP_CMS_ENV` defaults to `local` when unset, and a local app serves the full internal spec at `/openapi.json` without a credential. Set `TSI_DPDP_CMS_ENV` explicitly on every deployed host.

## Limits of the public document

- Descriptions in the public file are the first paragraph of each docstring, with the leading ticket reference removed. The rest of a docstring (review findings, environment variables, storage details) stays in the internal file. Write a docstring's first paragraph for an outside reader.
- `/api/v1/public/operator/sso_login` needs no credential but is the console's sign-on, so it is in the internal file only.
- GET is listed only where it can succeed. Query values are strings and are validated like a body, so a read whose required parameter is a number is documented as POST only.
- The wallet endpoint is documented as `/api/v1/client/wallet/sync` with its actions; calling the wallet with a target function name directly also works and is not listed separately.
