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
- Or run the app with `TSI_DPDP_CMS_ENV=local` and open `/docs`. It shows the internal spec.

## What the documents contain

- One operation per function: `POST /api/v1/{category}/{service}/{func}`, plus `GET` where the function is a read.
- Request bodies are the validator schemas the server enforces at runtime, converted to the OpenAPI 3.0 subset. A conditional rule (`if`/`then`) cannot be expressed in OpenAPI 3.0; it is kept as text under `x-conditional-rule` and is still enforced by the server.
- The credential each operation accepts, and under `x-required-scope` / `x-required-permission` the API key scope or role permission it needs.
- One shared error body for every error status.
- Descriptions come from the code's docstrings. A function without one has no description.

## What they do not contain

- Response bodies. Success responses are documented as a free-form JSON object; per-function response schemas are not specified yet.
- The legacy routes as separate operations. `/api/v1/{category}/{service}` with `_func` in the body is the same call and is described once in each document's introduction.

`x-unrouted` in the internal document lists validator schemas that no service implements, and allowed functions that have no schema.

## Production

A production deployment does not serve a spec or Swagger UI, by design: `/docs` and `/redoc` are disabled outside the local environment, and nginx answers 404 for `/docs`, `/redoc` and `/openapi.json`. These files are the way to share the reference.
