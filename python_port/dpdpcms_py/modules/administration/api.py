"""Public surface of the administration package.

Other modules and extensions import from here only, never from the files
behind it. Names resolve on first use, so importing this module does not import
the package's implementation.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS = {
    "authenticated_user_id": "identity",
    "has_permission": "roles",
    "legal_hold_for": "retention",
    "operator_fiduciary_id": "identity",
    "require_audit_access": "roles",
    "resolve_fiduciary": "tenancy",
    "retention_for": "retention",
    "retention_for_purposes": "retention",
    "role_permissions": "roles",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    try:
        target = _EXPORTS[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    return getattr(import_module(f"{__package__}.{target}"), name)
