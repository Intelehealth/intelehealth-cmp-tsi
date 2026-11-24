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

import argparse
import inspect
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dpdpcms_py import main as app_main
from dpdpcms_py.kernel.config import VALIDATOR_ROOT
from dpdpcms_py.kernel.service import Service
from dpdpcms_py.modules.administration.roles import MFA_EXEMPT_FUNCS, required_permission
from dpdpcms_py.modules.consent_lifecycle.wallet import WALLET_ACTIONS
from dpdpcms_py.registry import SERVICE_REGISTRY

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
    produces: tuple[str, ...] = ("application/json",)


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


def _accepts_string(schema: dict) -> bool:
    return schema.get("type") == "string" or any(_accepts_string(sub) for sub in schema.get("anyOf", []))


def _get_usable(service: str, func: str) -> bool:
    """Whether a GET of `func` can succeed.

    The dispatcher allows GET for reads only, and validates the query string
    against the same schema as a body. Query values are strings, so a function
    whose required parameter is a number or a list can never pass over GET.
    """
    if not app_main._is_read_classified(service, func):
        return False
    schema = request_schema(func)
    return all(_accepts_string(schema.get("properties", {}).get(name, {})) for name in schema.get("required", []))


_MEDIA_BY_RETURN = {"str": "text/plain", "bytes": "application/pdf"}


def _produces(method: Any) -> tuple[str, ...]:
    """Success media types, from the return annotation (`_json_response` in main.py)."""
    annotation = inspect.signature(method).return_annotation
    kinds = [part.strip() for part in annotation.split("|")] if isinstance(annotation, str) else []
    if kinds and all(kind in _MEDIA_BY_RETURN for kind in kinds):
        return tuple(_MEDIA_BY_RETURN[kind] for kind in kinds)
    return ("application/json",)


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
    method = getattr(SERVICE_REGISTRY[service], func)
    description = inspect.getdoc(method)
    if service == "wallet":
        description = _wallet_description(description)
    return Operation(
        category=category,
        service=service,
        func=func,
        methods=("get", "post") if _get_usable(service, func) else ("post",),
        success_status=201 if func.startswith(CREATED_PREFIXES) else 200,
        security=security,
        scope=scope,
        permission=permission,
        description=description,
        produces=_produces(method),
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
# Callable without a credential, but not part of the integrator API: operator
# single sign-on is the admin console's login.
PUBLIC_AUDIENCE_EXCLUDED = {("public", "operator", "sso_login")}
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
    "429": "Too Many Requests",
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

_SUBSCHEMA_LISTS = ("anyOf", "allOf", "oneOf")
_SUBSCHEMA_SINGLE = ("items", "additionalProperties", "not")
_CONDITIONAL_KEYS = ("if", "then", "else")
# The JSON Schema keywords an OpenAPI 3.0 schema object may carry as they are.
_PLAIN_KEYWORDS = frozenset(
    (
        "type required enum description title format pattern default "
        "minLength maxLength minimum maximum multipleOf "
        "minItems maxItems uniqueItems minProperties maxProperties"
    ).split()
)


def _unsupported(keyword: str) -> ValueError:
    return ValueError(
        f"{keyword!r} in a validator schema cannot be expressed in OpenAPI 3.0; "
        "teach dpdpcms_py.openapi_gen._convert how to document it."
    )


def _convert(node: Any) -> Any:
    """Rewrite a draft-07 schema node into the subset OpenAPI 3.0.3 allows."""
    if not isinstance(node, dict):
        return node
    out: dict[str, Any] = {}
    conditional = {key: node[key] for key in _CONDITIONAL_KEYS if key in node}
    for key, value in node.items():
        if key == "$schema" or key in _CONDITIONAL_KEYS:
            continue
        if key == "properties" and isinstance(value, dict):
            out[key] = {name: _convert(sub) for name, sub in value.items()}
        elif key in _SUBSCHEMA_LISTS and isinstance(value, list):
            out[key] = [_convert(sub) for sub in value]
        elif key in _SUBSCHEMA_SINGLE and isinstance(value, (dict, bool)):
            out[key] = _convert(value)
        elif key in _PLAIN_KEYWORDS:
            out[key] = value
        else:
            # Fail loudly: a keyword passed through unchecked would make the
            # document invalid while every test stayed green.
            raise _unsupported(key)
    if conditional:
        # OpenAPI 3.0 has no if/then/else. The rule is still enforced at
        # runtime; it is kept here as text so a reader can see it.
        out["x-conditional-rule"] = json.dumps(conditional, sort_keys=True)
    kinds = out.get("type")
    if isinstance(kinds, list):
        concrete = [kind for kind in kinds if kind != "null"]
        if not concrete:
            raise _unsupported("type: [null]")
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


_TICKET_PREFIX = re.compile(r"^[A-Z]{1,4}\d{0,2}-\d+[a-z]?:\s*")


def _public_text(text: str) -> str:
    """A docstring or schema note as an integrator may read it.

    Docstrings are written for maintainers: after the first paragraph they
    cite review findings, environment variables and storage details. The public
    document carries the first paragraph only, without its ticket reference.
    """
    first = " ".join(text.strip().split("\n\n")[0].split())
    first = _TICKET_PREFIX.sub("", first)
    return first[:1].upper() + first[1:]


def _public_schema(node: Any) -> Any:
    if isinstance(node, list):
        return [_public_schema(sub) for sub in node]
    if not isinstance(node, dict):
        return node
    out = {key: _public_schema(value) for key, value in node.items()}
    if isinstance(out.get("description"), str):
        out["description"] = _public_text(out["description"])
    return out


def _description(op: Operation, audience: str) -> str | None:
    text = op.description
    if text and audience == "public" and op.service != "wallet":
        text = _public_text(text)
    parts = [text] if text else []
    if op.scope:
        parts.append(f"Requires API key scope {op.scope}.")
    if op.permission:
        parts.append(f"Requires permission {op.permission}.")
    return "\n\n".join(parts) or None


def _query_parameters(schema: dict) -> list[dict]:
    required = set(schema.get("required", []))
    # Query values are strings: a parameter the validator wants as a number or
    # a list is not offered over GET.
    return [
        {"name": name, "in": "query", "required": name in required, "schema": sub}
        for name, sub in sorted(schema.get("properties", {}).items())
        if name != "_func" and _accepts_string(sub)
    ]


_SUCCESS_SCHEMAS = {
    "application/json": {"type": "object", "additionalProperties": True},
    "text/plain": {"type": "string"},
    "application/pdf": {"type": "string", "format": "binary"},
}


def _path_item(op: Operation, audience: str) -> dict:
    schema = request_schema(op.func)
    if audience == "public":
        schema = _public_schema(schema)
    responses: dict[str, dict] = {
        str(op.success_status): {
            "description": "Created" if op.success_status == 201 else "OK",
            "content": {media: {"schema": _SUCCESS_SCHEMAS[media]} for media in op.produces},
        }
    }
    for status in ERROR_STATUSES:
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
        description = _description(op, audience)
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
    "The function name may instead be sent as `_func` in the body to `/api/v1/{category}/{service}`; "
    "when both are given, the body's `_func` is the one that runs.\n\n"
    "The body is validated against the function's schema before it runs; a failure is a 400 "
    "whose `message` lists what is wrong.\n\n"
    "**Tenancy.** On the client API, `fiduciary_id` is taken from the credential. A value sent "
    "in the body is overridden, so a key or token can never read or write another fiduciary's "
    "records. With a principal token, `user_id` is taken from the token too; a `user_id` in the "
    "body that does not match it is refused with 403. A function under `/api/v1/public/` has no "
    "credential and takes `fiduciary_id` from the body.\n\n"
    "**GET.** A function may be called with GET only when it is a read; parameters then travel "
    "in the query string. Query values are strings and are validated like a body, so GET is "
    "documented only where every required parameter accepts a string, and only those parameters "
    "are listed. Everything else is POST-only (405 otherwise). A credential is never read from "
    "the query string.\n\n"
    "**Errors.** Every error has the same body: `timestamp`, `status`, `error`, `message`, `path`.\n\n"
    "**Authentication (client API).** Either an application API key (`X-API-Key` and "
    "`X-API-Secret` headers, together) or a data principal's bearer token. An API key carries "
    "scopes (READ, WRITE, PURGE); each function states the scope it needs, and a key without the "
    "scope gets 401. PURGE functions do "
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
    "**Bootstrap.** `/api/v1/bootstrap/` accepts initial setup only, with the bootstrap token "
    "(the `X-Bootstrap-Token` header, or `bootstrap_token` in the body).\n\n"
    "`/api/v1/public/operator/sso_login` is the console's single sign-on; it is left out of the "
    "public document.\n\n"
    "`x-unrouted` at the top of this document lists validator schemas that no service "
    "implements, and allowed functions that have no schema."
)


def build_spec(audience: str) -> dict:
    """The OpenAPI 3.0.3 document for `audience` ("public" or "internal")."""
    categories = AUDIENCE_CATEGORIES[audience]
    ops = [op for op in operations() if op.category in categories]
    if audience == "public":
        ops = [op for op in ops if (op.category, op.service, op.func) not in PUBLIC_AUDIENCE_EXCLUDED]
    used = {name for op in ops for requirement in _security(op) for name in requirement}
    spec: dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {
            "title": TITLES[audience],
            "version": "1",
            "description": _INTRO_COMMON + (_INTRO_INTERNAL if audience == "internal" else ""),
        },
        "tags": [{"name": service} for service in sorted({op.service for op in ops})],
        "paths": {f"/api/v1/{op.category}/{op.service}/{op.func}": _path_item(op, audience) for op in ops},
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


# ── files ───────────────────────────────────────────────────────────────────

OUTPUT_DIR = Path(__file__).resolve().parents[2] / "docs" / "api"
OUTPUTS = {"public": "openapi-public.json", "internal": "openapi-internal.json"}


def render(audience: str) -> str:
    return json.dumps(build_spec(audience), indent=2, sort_keys=True) + "\n"


def write_all(directory: Path | None = None) -> list[Path]:
    target = directory or OUTPUT_DIR
    target.mkdir(parents=True, exist_ok=True)
    written = []
    for audience, name in OUTPUTS.items():
        path = target / name
        path.write_text(render(audience), encoding="utf-8", newline="\n")
        written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m dpdpcms_py.openapi_gen", description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="write nothing; exit 1 if a committed spec is stale")
    args = parser.parse_args(argv)
    if not args.check:
        for path in write_all():
            print(path)
        return 0
    stale = [
        OUTPUT_DIR / name
        for audience, name in OUTPUTS.items()
        if not (OUTPUT_DIR / name).exists() or (OUTPUT_DIR / name).read_text(encoding="utf-8") != render(audience)
    ]
    for path in stale:
        print(f"stale: {path} (regenerate with: python -m dpdpcms_py.openapi_gen)", file=sys.stderr)
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
