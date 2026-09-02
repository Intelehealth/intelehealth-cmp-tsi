from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response

from .config import WEB_ROOT, settings
from .context import RequestContext
from .errors import ApiError, error_body
from .security import api_key_valid, bearer_token, decode_token
from .services import SERVICE_REGISTRY
from .validators import validate_payload


log = logging.getLogger("dpdpcms")

ADMIN_NOAUTH_FUNCS = {"reset_password", "login", "verify_recovery_key", "reset_password_via_recovery"}
BOOTSTRAP_ALLOWED = {("setup", "initial_setup")}
PUBLIC_ALLOWED_FUNCS = {"principal_login", "list_active_fiduciaries", "list_fiduciary_personas", "request_principal_otp"}
CLIENT_ALLOWED_FUNCS = {
    "record_consent", "get_active_consent", "get_policy", "get_active_policy",
    "link_user", "submit_grievance", "get_grievance", "validate_consent",
    "list_consent_history", "list_user_grievances", "get_consent_record_details",
    "withdraw_consent", "erasure_request", "list_purge_requests", "update_purge_status",
    "list_notifications", "mark_notification_read", "record_parent_consent",
    "list_active_policies",
}
CLIENT_FUNC_SCOPES = {
    "record_consent": "WRITE", "record_parent_consent": "WRITE", "link_user": "WRITE",
    "withdraw_consent": "WRITE", "submit_grievance": "WRITE",
    "mark_notification_read": "WRITE", "erasure_request": "WRITE",
    "get_active_consent": "READ", "list_consent_history": "READ",
    "get_consent_record_details": "READ", "validate_consent": "READ",
    "get_grievance": "READ", "list_user_grievances": "READ", "get_policy": "READ",
    "get_active_policy": "READ", "list_notifications": "READ",
    "list_active_policies": "READ",
    "list_purge_requests": "PURGE", "update_purge_status": "PURGE",
}


_docs = "/docs" if settings.environment == "local" else None
app = FastAPI(title="TSI DPDP CMS Python", docs_url=_docs, redoc_url=_docs and "/redoc")


@app.middleware("http")
async def headers(request: Request, call_next):
    origin = request.headers.get("origin")
    if request.method == "OPTIONS":
        response = Response(status_code=200)
    else:
        response = await call_next(request)
    if settings.allowed_origins and origin in settings.allowed_origins:
        response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Origin, Content-Type, Accept, Authorization, X-API-Key, X-API-Secret"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


class _DbJSONResponse(JSONResponse):
    """Rows come back from psycopg with UUID / datetime / Decimal values, which
    the stdlib encoder cannot handle. Stringify anything it does not know."""

    def render(self, content: Any) -> bytes:
        return json.dumps(content, ensure_ascii=False, allow_nan=False, default=str).encode("utf-8")


def _json_response(data: Any, status: int = 200) -> Response:
    if isinstance(data, str):
        return PlainTextResponse(data)
    return _DbJSONResponse(data if data is not None else {}, status_code=status)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


async def payload_from(request: Request) -> dict:
    if request.method == "GET":
        return dict(request.query_params)
    try:
        body = await request.json()
        return body if isinstance(body, dict) else {}
    except Exception:
        form = await request.form()
        return dict(form)


def authenticate(ctx: RequestContext) -> None:
    func = ctx.func
    if ctx.category == "public":
        if func not in PUBLIC_ALLOWED_FUNCS:
            raise ApiError(403, "Forbidden", f"Function '{func}' is not allowed on the public API.")
        return
    if ctx.category == "bootstrap":
        if (ctx.service, ctx.func) not in BOOTSTRAP_ALLOWED:
            raise ApiError(403, "Forbidden", "Bootstrap is limited to initial setup.")
        return
    if ctx.category == "admin":
        if func in ADMIN_NOAUTH_FUNCS:
            return
        raw = bearer_token(ctx.headers) or ctx.payload.get("auth")
        token = decode_token(raw)
        if not token:
            raise ApiError(401, "Unauthorized", "Authentication failed.")
        ctx.auth_token = token
        return
    if ctx.category == "client":
        if func not in CLIENT_ALLOWED_FUNCS:
            raise ApiError(403, "Forbidden", f"Function '{func}' is not allowed for client API access.")
        required = CLIENT_FUNC_SCOPES.get(func)
        principal_claims = decode_token(bearer_token(ctx.headers))
        if principal_claims and principal_claims.get("typ") == "principal":
            if required == "PURGE":
                raise ApiError(403, "Forbidden", "PURGE operations are not permitted via Principal tokens.")
            ctx.fiduciary_id = str(principal_claims.get("fid"))
            ctx.principal_user_id = str(principal_claims.get("sub"))
            ctx.auth_via_principal_jwt = True
            if ctx.payload.get("user_id") and ctx.payload["user_id"] != ctx.principal_user_id:
                raise ApiError(403, "Forbidden", "User ID mismatch: token does not authorize access to the requested principal.")
            return
        ok, fid, scopes = api_key_valid(ctx.headers.get("x-api-key") or ctx.headers.get("X-API-Key"), ctx.headers.get("x-api-secret") or ctx.headers.get("X-API-Secret"))
        if not ok or (required and required not in scopes):
            raise ApiError(401, "Unauthorized", "Invalid or inactive API Key/Secret.")
        ctx.fiduciary_id = fid
        ctx.permissions = scopes


async def dispatch(request: Request, category: str, service: str) -> Response:
    path = request.url.path
    try:
        if request.method not in {"POST", "GET"}:
            raise ApiError(405, "Method Not Allowed", "Only POST method is supported.")
        payload = await payload_from(request)
        if request.method == "POST":
            errors = validate_payload(payload)
            if errors:
                raise ApiError(400, "Bad Request", "; ".join(errors))
        ctx = RequestContext(path=path, category=category, service=service, payload=payload, headers={k: v for k, v in request.headers.items()}, method=request.method)
        service_cls = SERVICE_REGISTRY.get(service)
        if not service_cls:
            raise ApiError(404, "Not Found", f"API endpoint not found: {path}")
        authenticate(ctx)
        result = service_cls().handle(ctx)
        status = 201 if ctx.func.startswith(("create_", "generate_", "record_", "report_")) else 200
        return _json_response(result, status=status)
    except ApiError as exc:
        return JSONResponse(error_body(exc.status, exc.error, exc.message, path), status_code=exc.status)
    except Exception:
        log.exception("Unhandled error on %s", path)
        return JSONResponse(error_body(500, "Internal Server Error", "An unexpected error occurred.", path), status_code=500)


@app.api_route("/api/v1/{service}", methods=["POST", "GET", "OPTIONS"])
async def legacy_api(request: Request, service: str):
    return await dispatch(request, "admin", service)


@app.api_route("/api/v1/{category}/{service}", methods=["POST", "GET", "OPTIONS"])
async def categorized_api(request: Request, category: str, service: str):
    if category not in {"admin", "client", "public", "bootstrap"}:
        return await dispatch(request, "admin", category)
    return await dispatch(request, category, service)


@app.get("/{full_path:path}")
async def static_or_index(full_path: str):
    rel = full_path or "index.html"
    path = (WEB_ROOT / rel).resolve()
    # A directory request (/rights, /console/dpo) serves that directory's own
    # index.html; only fall back to the site root when nothing else matches.
    if path.is_dir():
        # Redirect to the trailing-slash form first. Serving the directory index at
        # /rights leaves the browser's base URL one level too high, so the page's
        # relative assets (portal.js) resolve to /portal.js, hit the root-index
        # fallback below, and come back as text/html -- the script is then refused.
        if full_path and not full_path.endswith("/"):
            return RedirectResponse(f"/{full_path}/", status_code=308)
        path = path / "index.html"
    if not str(path).startswith(str(WEB_ROOT.resolve())) or not path.exists() or path.is_dir():
        path = WEB_ROOT / "index.html"
    if path.suffix.lower() == ".html":
        text = path.read_text(encoding="utf-8", errors="ignore")
        if settings.brand_name != "TSI DPDP CMS":
            text = text.replace("TSI DPDP CMS", settings.brand_name)
        return HTMLResponse(text)
    return FileResponse(path)
