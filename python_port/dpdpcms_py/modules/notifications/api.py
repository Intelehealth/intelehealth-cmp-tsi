"""Public surface of the notifications package.

Other modules and extensions import from here only, never from the files
behind it. Names resolve on first use, so importing this module does not import
the package's implementation.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS = {
    "DEFAULT_NOTIFICATION_MESSAGES": "defaults",
    "NOTIFICATION_LANGUAGES": "defaults",
    "_dpo_recipient": "dpo_notify",
    "_notify": "dpo_notify",
    "enqueue_alert_dispatch": "alerts",
    "notify_processors": "alert_store",
    "queue_webhook": "webhooks",
    "record_alert": "alert_store",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    try:
        target = _EXPORTS[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    return getattr(import_module(f"{__package__}.{target}"), name)
