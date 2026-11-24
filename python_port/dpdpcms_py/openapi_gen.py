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
from dataclasses import dataclass

from . import main as app_main
from .config import VALIDATOR_ROOT
from .services import SERVICE_REGISTRY
from .services.base import Service
from .services.consent import WALLET_ACTIONS
from .services.roles import required_permission

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
