"""Generate the OpenAPI specs in docs/api/ from the code's own tables.

The app has three catch-all routes that dispatch on `_func`, so FastAPI's
built-in schema shows nothing useful. This module enumerates every
(category, service, function) the dispatcher accepts, from SERVICE_REGISTRY,
the validator schemas and the allow-list / permission tables in main.py and
services/roles.py. It reads tables and files only: no database, no network.

    python -m dpdpcms_py.openapi_gen          # write docs/api/*.json
    python -m dpdpcms_py.openapi_gen --check  # exit 1 if they are stale
"""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
from typing import Any

from . import main as app_main
from .config import VALIDATOR_ROOT
from .services import SERVICE_REGISTRY
from .services.base import Service
from .services.consent import WALLET_ACTIONS
from .services.roles import MFA_EXEMPT_FUNCS, required_permission

CREATED_PREFIXES = ("create_", "generate_", "record_", "report_", "submit_")


@dataclass(frozen=True)
class Operation:
    category: str
    service: str
    func: str
    methods: tuple[str, ...]
    success_status: int
    security: tuple[str, ...]
    scope: str | None
    permission: str | None
    description: str | None


def _schema_funcs() -> set[str]:
    return {path.stem for path in VALIDATOR_ROOT.glob("*.jschema")}


def _defined_funcs(service_cls: type) -> set[str]:
    """Public method names a service class defines itself (not Service helpers)."""
    names: set[str] = set()
    for klass in service_cls.__mro__:
        if klass is Service:
            break
        names.update(
            name
            for name, value in vars(klass).items()
            if inspect.isfunction(value) and not name.startswith("_") and name != "handle"
        )
    return names


def _service_funcs() -> dict[str, list[str]]:
    schemas = _schema_funcs()
    return {service: sorted(_defined_funcs(cls) & schemas) for service, cls in SERVICE_REGISTRY.items()}


def _wallet_description(base: str | None) -> str:
    actions = "; ".join(f"`{action}` runs `{target}`" for action, target in sorted(WALLET_ACTIONS.items()))
    note = f"The `action` field selects the function that runs and whose schema and scope apply: {actions}."
    return f"{base}\n\n{note}" if base else note


def _make(category: str, service: str, func: str) -> Operation:
    scope = permission = None
    if category == "admin":
        security = () if func in app_main.ADMIN_NOAUTH_FUNCS else ("operatorBearer",)
        permission = None if func in app_main.ADMIN_NOAUTH_FUNCS else required_permission(service, func)
    elif category == "client":
        scope = app_main.CLIENT_FUNC_SCOPES.get(func)
        security = ("apiKey",) if scope == "PURGE" else ("apiKey", "principalBearer")
    elif category == "bootstrap":
        security = ("bootstrapToken",)
    else:
        security = ()
    description = inspect.getdoc(getattr(SERVICE_REGISTRY[service], func))
    if service == "wallet":
        description = _wallet_description(description)
    return Operation(
        category=category,
        service=service,
        func=func,
        methods=("get", "post") if app_main._is_read_classified(service, func) else ("post",),
        success_status=201 if func.startswith(CREATED_PREFIXES) else 200,
        security=security,
        scope=scope,
        permission=permission,
        description=description,
    )


def operations() -> list[Operation]:
    """Every documented (category, service, func), sorted."""
    found: list[Operation] = []
    for service, funcs in _service_funcs().items():
        for func in funcs:
            # The wallet resolves `action` to another service's function; it is
            # documented as its one client operation, not per category.
            if service != "wallet":
                found.append(_make("admin", service, func))
            if func in app_main.CLIENT_ALLOWED_FUNCS:
                found.append(_make("client", service, func))
            if func in app_main.PUBLIC_ALLOWED_FUNCS:
                found.append(_make("public", service, func))
            if (service, func) in app_main.BOOTSTRAP_ALLOWED:
                found.append(_make("bootstrap", service, func))
    return sorted(found, key=lambda o: (o.category, o.service, o.func))


def unrouted() -> dict[str, list[str]]:
    """Schemas no service implements, and allowed functions with no schema."""
    schemas = _schema_funcs()
    implemented = set().union(*(_defined_funcs(cls) for cls in SERVICE_REGISTRY.values()))
    allowed = app_main.CLIENT_ALLOWED_FUNCS | app_main.PUBLIC_ALLOWED_FUNCS
    return {
        "schema_without_method": sorted(schemas - implemented),
        "allowed_without_schema": sorted(allowed - schemas),
    }


# ── spec documents ──────────────────────────────────────────────────────────

AUDIENCE_CATEGORIES = {
    "public": ("client", "public"),
    "internal": ("admin", "bootstrap", "client", "public"),
}
TITLES = {"public": "TSI DPDP CMS API", "internal": "TSI DPDP CMS API (internal)"}

SECURITY_SCHEMES: dict[str, dict] = {
    "operatorBearer": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
        "description": "Operator session token returned by `login` (admin API).",
    },
    "principalBearer": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
        "description": "Data principal token returned by `principal_login`. Not accepted for PURGE-scope functions.",
    },
    "apiKey": {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
        "description": "Application API key. Always sent together with X-API-Secret.",
    },
    "apiSecret": {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Secret",
        "description": "Secret for the API key in X-API-Key.",
    },
    "bootstrapToken": {
        "type": "apiKey",
        "in": "header",
        "name": "X-Bootstrap-Token",
        "description": "One-time bootstrap token, for initial setup only.",
    },
}

ERROR_STATUSES = {
    "400": "Bad Request",
    "401": "Unauthorized",
    "403": "Forbidden",
    "404": "Not Found",
    "405": "Method Not Allowed",
    "409": "Conflict",
    "500": "Internal Server Error",
}
ERROR_SCHEMA = {
    "type": "object",
    "properties": {
        "timestamp": {"type": "string", "format": "date-time"},
        "status": {"type": "integer"},
        "error": {"type": "string"},
        "message": {"type": "string"},
        "path": {"type": "string"},
    },
    "required": ["timestamp", "status", "error", "message", "path"],
}

_SUBSCHEMA_MAPS = ("properties", "patternProperties", "definitions")
_SUBSCHEMA_LISTS = ("anyOf", "allOf", "oneOf")
_SUBSCHEMA_SINGLE = ("items", "additionalProperties", "not")
_CONDITIONAL_KEYS = ("if", "then", "else")


def _convert(node: Any) -> Any:
    """Rewrite a draft-07 schema node into the subset OpenAPI 3.0.3 allows."""
    if not isinstance(node, dict):
        return node
    out: dict[str, Any] = {}
    conditional = {key: node[key] for key in _CONDITIONAL_KEYS if key in node}
    for key, value in node.items():
        if key == "$schema" or key in _CONDITIONAL_KEYS:
            continue
        if key in _SUBSCHEMA_MAPS and isinstance(value, dict):
            out[key] = {name: _convert(sub) for name, sub in value.items()}
        elif key in _SUBSCHEMA_LISTS and isinstance(value, list):
            out[key] = [_convert(sub) for sub in value]
        elif key in _SUBSCHEMA_SINGLE:
            out[key] = _convert(value)
        else:
            out[key] = value
    if conditional:
        # OpenAPI 3.0 has no if/then/else. The rule is still enforced at
        # runtime; it is kept here as text so a reader can see it.
        out["x-conditional-rule"] = json.dumps(conditional, sort_keys=True)
    kinds = out.get("type")
    if isinstance(kinds, list):
        concrete = [kind for kind in kinds if kind != "null"]
        if len(concrete) != len(kinds):
            out["nullable"] = True
        if len(concrete) == 1:
            out["type"] = concrete[0]
        else:
            del out["type"]
            out["anyOf"] = [{"type": kind} for kind in concrete]
    return out


def request_schema(func: str, *, func_in_path: bool = True) -> dict:
    """The validator schema for `func`, as an OpenAPI 3.0.3 schema object."""
    raw = json.loads((VALIDATOR_ROOT / f"{func}.jschema").read_text(encoding="utf-8"))
    schema = _convert(raw)
    if schema.get("title") == "Generated schema for Root":
        del schema["title"]
    if func_in_path and "required" in schema:
        schema["required"] = [name for name in schema["required"] if name != "_func"]
        if not schema["required"]:
            del schema["required"]
    return schema


def _security(op: Operation) -> list[dict]:
    return [{"apiKey": [], "apiSecret": []} if name == "apiKey" else {name: []} for name in op.security]


def _description(op: Operation) -> str | None:
    parts = [op.description] if op.description else []
    if op.scope:
        parts.append(f"Requires API key scope {op.scope}.")
    if op.permission:
        parts.append(f"Requires permission {op.permission}.")
    return "\n\n".join(parts) or None


def _query_parameters(schema: dict) -> list[dict]:
    required = set(schema.get("required", []))
    return [
        {"name": name, "in": "query", "required": name in required, "schema": sub}
        for name, sub in sorted(schema.get("properties", {}).items())
        if name != "_func"
    ]


def _path_item(op: Operation) -> dict:
    schema = request_schema(op.func)
    responses: dict[str, dict] = {
        str(op.success_status): {
            "description": "Created" if op.success_status == 201 else "OK",
            "content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}}},
        }
    }
    for status in ERROR_STATUSES:
        if status == "401" and not op.security:
            continue
        responses[status] = {"$ref": f"#/components/responses/Error{status}"}
    item: dict[str, dict] = {}
    for method in op.methods:
        operation: dict[str, Any] = {
            "operationId": f"{op.category}_{op.service}_{op.func}" + ("_get" if method == "get" else ""),
            "tags": [op.service],
            "summary": op.func,
            "security": _security(op),
            "responses": responses,
        }
        description = _description(op)
        if description:
            operation["description"] = description
        if op.scope:
            operation["x-required-scope"] = op.scope
        if op.permission:
            operation["x-required-permission"] = op.permission
        if method == "get":
            parameters = _query_parameters(schema)
            if parameters:
                operation["parameters"] = parameters
        else:
            operation["requestBody"] = {"required": True, "content": {"application/json": {"schema": schema}}}
        item[method] = operation
    return item


_INTRO_COMMON = (
    "Every function is called as `POST /api/v1/{category}/{service}/{func}` with a JSON body. "
    "The function name may instead be sent as `_func` in the body to `/api/v1/{category}/{service}`.\n\n"
    "The body is validated against the function's schema before it runs; a failure is a 400 "
    "whose `message` lists what is wrong.\n\n"
    "**Tenancy.** `fiduciary_id` is taken from the credential. A value sent in the body is "
    "overridden, so a key or token can never read or write another fiduciary's records. "
    "With a principal token, `user_id` is bound to the token's principal in the same way.\n\n"
    "**GET.** A function may be called with GET only when it is a read; parameters then travel "
    "in the query string. Everything else is POST-only (405 otherwise). A credential is never "
    "read from the query string.\n\n"
    "**Errors.** Every error has the same body: `timestamp`, `status`, `error`, `message`, `path`.\n\n"
    "**Authentication (client API).** Either an application API key (`X-API-Key` and "
    "`X-API-Secret` headers, together) or a data principal's bearer token. An API key carries "
    "scopes (READ, WRITE, PURGE); each function states the scope it needs. PURGE functions do "
    "not accept a principal token. Functions under `/api/v1/public/` need no credential."
)
_INTRO_INTERNAL = (
    "\n\n**Authentication (admin API).** An operator bearer token from `login`. Every call must map "
    "to an ACTIVE operator; logout, deactivation or a password change revokes tokens at once. "
    "An account with MFA enabled must present an MFA-verified token for every function except "
    + ", ".join(f"`{name}`" for name in sorted(MFA_EXEMPT_FUNCS))
    + ".\n\n"
    "**Permissions (admin API).** Each function requires `<resource>:<action>`, checked against "
    "the operator's role in the roles table. `manage` implies `write`, and `write` implies "
    "`read`. The ADMIN role has full access. An operator bound to a fiduciary is confined to it; "
    "only a global ADMIN selects a fiduciary through the body.\n\n"
    "**Bootstrap.** `/api/v1/bootstrap/` accepts initial setup only, with the bootstrap token.\n\n"
    "`x-unrouted` at the top of this document lists validator schemas that no service "
    "implements, and allowed functions that have no schema."
)


def build_spec(audience: str) -> dict:
    """The OpenAPI 3.0.3 document for `audience` ("public" or "internal")."""
    categories = AUDIENCE_CATEGORIES[audience]
    ops = [op for op in operations() if op.category in categories]
    used = {name for op in ops for requirement in _security(op) for name in requirement}
    spec: dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {
            "title": TITLES[audience],
            "version": "1",
            "description": _INTRO_COMMON + (_INTRO_INTERNAL if audience == "internal" else ""),
        },
        "tags": [{"name": service} for service in sorted({op.service for op in ops})],
        "paths": {f"/api/v1/{op.category}/{op.service}/{op.func}": _path_item(op) for op in ops},
        "components": {
            "securitySchemes": {name: SECURITY_SCHEMES[name] for name in sorted(used)},
            "schemas": {"Error": ERROR_SCHEMA},
            "responses": {
                f"Error{status}": {
                    "description": text,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
                }
                for status, text in ERROR_STATUSES.items()
            },
        },
    }
    if audience == "internal":
        spec["x-unrouted"] = unrouted()
    return spec
