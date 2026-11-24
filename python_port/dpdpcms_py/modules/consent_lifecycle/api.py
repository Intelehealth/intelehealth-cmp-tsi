"""Public surface of the consent_lifecycle package.

Other modules and extensions import from here only, never from the files
behind it. Names resolve on first use, so importing this module does not import
the package's implementation.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS = {
    "activate_policy_if_complete": "notice",
    "close_due_time_bound_purposes": "sweeps",
    "close_purpose_exec": "purpose_lifecycle",
    "served_policy_version": "policy_store",
    "sync_purpose_lifecycle": "purpose_lifecycle",
    "validate_duration_flags": "purpose_lifecycle",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    try:
        target = _EXPORTS[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    return getattr(import_module(f"{__package__}.{target}"), name)
