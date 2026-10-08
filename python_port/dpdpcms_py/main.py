from __future__ import annotations

import hmac
import json
import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response

from . import db
from .config import WEB_ROOT, settings
from .context import RequestContext
from .errors import ApiError, error_body
from .security import api_key_valid, bearer_token, decode_token
from .services import SERVICE_REGISTRY
from .services.consent import resolve_wallet_action
from .services.roles import FUNC_PERMISSIONS, MFA_EXEMPT_FUNCS, READ_PREFIXES, enforce_role_permission
from .validators import validate_payload

log = logging.getLogger("dpdpcms")

ADMIN_NOAUTH_FUNCS = {"reset_password", "login", "verify_recovery_key", "reset_password_via_recovery"}
BOOTSTRAP_ALLOWED = {("setup", "initial_setup")}
PUBLIC_ALLOWED_FUNCS = {
    # SA-06: operator single sign-on (the IdP's id_token is the credential).
    "sso_login",
    "principal_login",
    "list_active_fiduciaries",
    "list_fiduciary_personas",
    "request_principal_otp",
}
CLIENT_ALLOWED_FUNCS = {
    "record_consent",
    "get_active_consent",
    "get_policy",
    "get_active_policy",
    "link_user",
    "submit_grievance",
    "get_grievance",
    "validate_consent",
    "list_consent_history",
    "list_user_grievances",
    "get_consent_record_details",
    "withdraw_consent",
    "erasure_request",
    "list_purge_requests",
    "update_purge_status",
    "list_notifications",
    "mark_notification_read",
    "record_parent_consent",
    "list_active_policies",
    "sync",
    "create_nomination",
    "list_nominations",
    "revoke_nomination",
    "submit_correction",
    "list_corrections",
    # P1: consent-change alerts for fiduciaries/processors (BRD 4.4.2)
    "notify_alert",
    "acknowledge_alert",
    "list_alerts",
    # P1: fresh affirmative consent on a material policy change (BRD 4.1.3)
    "request_reconsent",
    # P2: principal downloads their own consent history (UD-04)
    "export_consent_history",
    # BRD traceability: withdrawal implications, grievance follow-up, purge proof
    "get_withdrawal_implications",
    "add_grievance_communication",
    "submit_grievance_feedback",
    "upload_grievance_attachment",
    "get_grievance_attachment",
    "confirm_purge_status",
}
CLIENT_FUNC_SCOPES = {
    "record_consent": "WRITE",
    "record_parent_consent": "WRITE",
    "link_user": "WRITE",
    "withdraw_consent": "WRITE",
    "submit_grievance": "WRITE",
    "mark_notification_read": "WRITE",
    "erasure_request": "WRITE",
    "get_active_consent": "READ",
    "list_consent_history": "READ",
    "get_consent_record_details": "READ",
    "validate_consent": "READ",
    "get_grievance": "READ",
    "list_user_grievances": "READ",
    "get_policy": "READ",
    "get_active_policy": "READ",
    "list_notifications": "READ",
    "list_active_policies": "READ",
    "list_purge_requests": "PURGE",
    "update_purge_status": "PURGE",
    "sync": "READ",
    "create_nomination": "WRITE",
    "list_nominations": "READ",
    "revoke_nomination": "WRITE",
    "submit_correction": "WRITE",
    "list_corrections": "READ",
    # P1: consent-change alerts for fiduciaries/processors (BRD 4.4.2)
    "notify_alert": "WRITE",
    "acknowledge_alert": "WRITE",
    "list_alerts": "READ",
    # P1: fresh affirmative consent on a material policy change (BRD 4.1.3)
    "request_reconsent": "WRITE",
    # P2: principal downloads their own consent history (UD-04)
    "export_consent_history": "READ",
    "get_withdrawal_implications": "READ",
    "add_grievance_communication": "WRITE",
    "submit_grievance_feedback": "WRITE",
    "upload_grievance_attachment": "WRITE",
    "get_grievance_attachment": "READ",
    "confirm_purge_status": "PURGE",
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
    response.headers["Access-Control-Allow-Headers"] = (
        "Origin, Content-Type, Accept, Authorization, X-API-Key, X-API-Secret"
    )
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
    if isinstance(data, bytes):
        # Binary exports (UD-04 PDF) are served as a download.
        return Response(
            data,
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="consent-history.pdf"'},
        )
    if isinstance(data, str):
        return PlainTextResponse(data)
    return _DbJSONResponse(data if data is not None else {}, status_code=status)


@app.get("/healthz")
async def healthz():
    tables = (
        "consent_records",
        "consent_policies",
        "data_principal",
        "fiduciaries",
        "grievances",
        "purge_requests",
        "audit_logs",
        "ropa_entries",
        "breach_incidents",
        "evidence_certificates",
    )
    try:
        with db.connection() as conn, conn.cursor() as cur:
            for table in tables:
                cur.execute("SELECT to_regclass(%s) AS table_name", (f"public.{table}",))
                row = cur.fetchone()
                if not row or not row.get("table_name"):
                    return JSONResponse(
                        {"status": "degraded", "detail": f"database schema is incomplete: missing {table}"},
                        status_code=503,
                    )
        return {"status": "ok"}
    except Exception as exc:
        return JSONResponse({"status": "unavailable", "detail": str(exc)}, status_code=503)


async def payload_from(request: Request) -> dict:
    if request.method == "GET":
        return dict(request.query_params)
    try:
        body = await request.json()
        return body if isinstance(body, dict) else {}
    except Exception:
        form = await request.form()
        return dict(form)


def _is_read_classified(service: str, func: str) -> bool:
    """SEC-17: a function may run over GET only when it is classified as a read.

    The same rule the role gate uses: side-effect-free prefixes, or an explicit
    `:read` entry in FUNC_PERMISSIONS. Everything else (a write, a
    `validate_*`, an MFA round-trip, logout) must be a POST. P6-05: client
    API-key READ scopes are folded in too, so `validate_consent` and `sync`,
    which the client callers may legitimately poll, are not wrongly refused a
    GET.
    """
    if func in MFA_EXEMPT_FUNCS:
        return False
    if CLIENT_FUNC_SCOPES.get(func) == "READ":
        return True
    if func.startswith(READ_PREFIXES):
        return True
    permission = FUNC_PERMISSIONS.get((service, func))
    return bool(permission and permission.endswith(":read"))


def client_ip(request: Request) -> str | None:
    """The caller's IP, used for audit and throttle buckets.

    P5-02: when the API sits behind a reverse proxy, every request arrives from
    the proxy and `request.client.host` is the proxy's address — so all
    operators would share one IP throttle bucket. X-Forwarded-For is honoured
    only when the immediate peer is a configured trusted proxy
    (TRUSTED_PROXY_IPS); a direct caller can never self-declare its identity.
    P6-04: the chain is walked RIGHT-to-LEFT, dropping trailing trusted hops, so
    a caller behind the proxy cannot force a spoofed hop at the front of the
    header to win — the rightmost non-trusted hop is the real client. Matches
    support exact IPs and CIDR ranges.
    """
    import ipaddress

    if request.client is None:
        return None
    peer = request.client.host

    def trusted(ip: str) -> bool:
        for entry in settings.trusted_proxy_ips or ():
            try:
                if "/" in entry and ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
            if entry == ip:
                return True
        return False

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and trusted(peer):
        chain = [hop.strip() for hop in forwarded.split(",") if hop.strip()]
        # Rightmost hop was appended by the nearest proxy. Walk right-to-left,
        # skipping hops that are themselves trusted proxies, and return the first
        # untrusted hop — that is the true client that entered the proxy fleet.
        for hop in reversed(chain):
            if trusted(hop):
                continue
            return hop
        return peer
    return peer


def _bootstrap_authorized(ctx: RequestContext) -> bool:
    supplied = (
        ctx.headers.get("x-bootstrap-token")
        or ctx.headers.get("X-Bootstrap-Token")
        or ctx.payload.get("bootstrap_token")
    )
    if not supplied:
        return False
    return hmac.compare_digest(str(supplied), settings.bootstrap_token)


def authenticate(ctx: RequestContext) -> None:
    func = ctx.func
    if ctx.category == "public":
        if func not in PUBLIC_ALLOWED_FUNCS:
            raise ApiError(403, "Forbidden", f"Function '{func}' is not allowed on the public API.")
        return
    if ctx.category == "bootstrap":
        if (ctx.service, ctx.func) not in BOOTSTRAP_ALLOWED:
            raise ApiError(403, "Forbidden", "Bootstrap is limited to initial setup.")
        if not _bootstrap_authorized(ctx):
            raise ApiError(401, "Unauthorized", "A valid bootstrap token is required.")
        return
    if ctx.category == "admin":
        if func in ADMIN_NOAUTH_FUNCS:
            return
        # SEC-17: a credential never comes from a ?auth= query parameter. The
        # query string is the only thing GET carries, so dropping the parameter
        # closes the "re-send a POST as GET to skip auth" vector twice over.
        raw = bearer_token(ctx.headers)
        token = decode_token(raw)
        if not token:
            raise ApiError(401, "Unauthorized", "Authentication failed.")
        # Principal and operator JWTs share a signing key, so the token type must
        # be checked: a principal token is never an operator session.
        if token.get("typ") == "principal" or not token.get("email"):
            raise ApiError(401, "Unauthorized", "Authentication failed.")
        # Every admin call must map to an ACTIVE operator. This also revokes the
        # tokens of deactivated accounts, and makes the database role (not the
        # role claim baked into the token) the one that is authorised.
        operator = db.one(
            f"""
            SELECT o.id, o.role, o.fiduciary_id, o.mfa_enabled,
                   EXTRACT(EPOCH FROM o.tokens_valid_after) AS valid_after,
                   EXISTS (SELECT 1 FROM revoked_tokens r WHERE r.jti = %s) AS revoked
            FROM operators o
            WHERE o.email_hmac = {db.hmac_expr()} AND o.status = 'ACTIVE' LIMIT 1
            """,
            (str(token.get("jti") or ""), *db.bind_hmac(token.get("email", ""))),
        )
        if not operator:
            raise ApiError(401, "Unauthorized", "Authentication failed.")
        # SA-05: logout revokes the one token; deactivation or a password change
        # revokes every token issued before it, immediately rather than at expiry.
        if operator.get("revoked") or (
            operator.get("valid_after") is not None and int(token.get("iat") or 0) < int(operator["valid_after"])
        ):
            raise ApiError(401, "Unauthorized", "This session has been revoked. Please sign in again.")
        # SA-06: an account with MFA enabled must present an mfa-verified token
        # for ANY function except the MFA round-trip itself and logout.
        if token.get("mfa") is not True and func not in MFA_EXEMPT_FUNCS and operator["mfa_enabled"]:
            raise ApiError(
                403,
                "Forbidden",
                "Multi-factor verification is required to continue. Call verify_mfa with the code from your authenticator app.",
            )
        ctx.auth_token = {**token, "role": operator["role"]}
        ctx.operator_id = str(operator["id"])
        # A fiduciary-scoped operator (DPO, OPERATOR, AUDITOR...) is bound to its
        # own tenant exactly like an API key: never trust a body-supplied
        # fiduciary_id. Only a global ADMIN selects a tenant via the payload.
        if operator.get("fiduciary_id") and str(operator["role"]).upper() != "ADMIN":
            ctx.fiduciary_id = str(operator["fiduciary_id"])
            ctx.payload["fiduciary_id"] = ctx.fiduciary_id
        # SA-02/SA-03: every admin function is gated by the roles table.
        enforce_role_permission(ctx)
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
            ctx.session_id = str(principal_claims.get("jti") or "") or None
            if ctx.payload.get("user_id") and ctx.payload["user_id"] != ctx.principal_user_id:
                raise ApiError(
                    403, "Forbidden", "User ID mismatch: token does not authorize access to the requested principal."
                )
            # A principal token is scoped to its own fiduciary: never trust a
            # fiduciary_id supplied in the request body.
            ctx.payload["fiduciary_id"] = ctx.fiduciary_id
            # The token names the principal; bind it so schema validation and the
            # service see the same user_id the caller is authorised for.
            ctx.payload["user_id"] = ctx.principal_user_id
            return
        ok, fid, scopes, app_id = api_key_valid(
            ctx.headers.get("x-api-key") or ctx.headers.get("X-API-Key"),
            ctx.headers.get("x-api-secret") or ctx.headers.get("X-API-Secret"),
        )
        if not ok or (required and required not in scopes):
            raise ApiError(401, "Unauthorized", "Invalid or inactive API Key/Secret.")
        ctx.fiduciary_id = fid
        ctx.permissions = scopes
        ctx.app_id = app_id
        # An API key is bound to one fiduciary: override any tenant id supplied in
        # the body so a key can never read or write another tenant's records.
        ctx.payload["fiduciary_id"] = ctx.fiduciary_id


async def dispatch(request: Request, category: str, service: str, func: str | None = None) -> Response:
    path = request.url.path
    try:
        if request.method not in {"POST", "GET"}:
            raise ApiError(405, "Method Not Allowed", "Only POST method is supported.")
        payload = await payload_from(request)
        if func and not payload.get("_func"):
            payload["_func"] = func
        # P4-02: normalise once so schema lookup, scope resolution and dispatch
        # all see the same function name.
        payload["_func"] = str(payload.get("_func") or "").strip().lower()
        if service == "wallet":
            # D14: authorise the operation the wallet action runs, not "sync".
            resolve_wallet_action(payload)
        if not payload["_func"]:
            raise ApiError(400, "Bad Request", "_func missing")
        ctx = RequestContext(
            path=path,
            category=category,
            service=service,
            payload=payload,
            headers={k: v for k, v in request.headers.items()},
            method=request.method,
            source_ip=client_ip(request),
        )
        service_cls = SERVICE_REGISTRY.get(service)
        if not service_cls:
            raise ApiError(404, "Not Found", f"API endpoint not found: {path}")
        authenticate(ctx)
        # P4-01: validate only once authenticate() has bound the token-derived
        # fields (fiduciary_id, a principal's user_id); a wallet call is checked
        # against the schema of the function its action resolved to.
        # SEC-17: validation runs on GET too. The advisory-lock-free re-send of a
        # POST as a GET is exactly how a caller skipped every one of the 142
        # schemas; `payload_from` still loads query parameters, so a GET body is
        # validated like any other.
        if request.method == "GET" and not _is_read_classified(service, ctx.func):
            raise ApiError(405, "Method Not Allowed", f"{ctx.func} is not a read and cannot be called with GET.")
        errors = validate_payload(ctx.payload)
        if errors:
            raise ApiError(400, "Bad Request", "; ".join(errors))
        result = service_cls().handle(ctx)
        status = 201 if ctx.func.startswith(("create_", "generate_", "record_", "report_", "submit_")) else 200
        return _json_response(result, status=status)
    except ApiError as exc:
        return JSONResponse(error_body(exc.status, exc.error, exc.message, path), status_code=exc.status)
    except Exception:
        log.exception("Unhandled error on %s", path)
        return JSONResponse(
            error_body(500, "Internal Server Error", "An unexpected error occurred.", path), status_code=500
        )


@app.api_route("/api/v1/{service}", methods=["POST", "GET", "OPTIONS"])
async def legacy_api(request: Request, service: str):
    return await dispatch(request, "admin", service)


@app.api_route("/api/v1/{category}/{service}", methods=["POST", "GET", "OPTIONS"])
async def categorized_api(request: Request, category: str, service: str):
    if category not in {"admin", "client", "public", "bootstrap"}:
        return await dispatch(request, "admin", category)
    return await dispatch(request, category, service)


@app.api_route("/api/v1/{category}/{service}/{func}", methods=["POST", "GET", "OPTIONS"])
async def categorized_api_func(request: Request, category: str, service: str, func: str):
    if category not in {"admin", "client", "public", "bootstrap"}:
        return await dispatch(request, "admin", category, func)
    return await dispatch(request, category, service, func)


@app.get("/{full_path:path}")
async def static_or_index(full_path: str):
    # CF-01: WEB-INF (validator schemas, server config) is never served, matching
    # the servlet container the Java original ran in. Checked per path segment,
    # case-insensitively and ignoring trailing dots (WEB-INF. resolves to WEB-INF on Windows).
    if any(
        part.strip().rstrip(". ").lower() in {"web-inf", "meta-inf"} for part in full_path.replace("\\", "/").split("/")
    ):
        return JSONResponse(error_body(404, "Not Found", "Not Found", f"/{full_path}"), status_code=404)
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
