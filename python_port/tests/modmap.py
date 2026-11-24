"""The pre-modularisation module names, for tests written against them.

Before the code was regrouped into BRD modules, one file (for example
`services/compliance.py`) held what is now several files in several packages.
Tests written then patch and read attributes on that one module. A ModuleGroup
keeps those tests meaning what they meant: reading an attribute finds it in
whichever successor file defines or imports it, and setting one sets it in
every successor file that has it, which is what patching the old single module
did. New tests should import the real modules instead.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_MISSING = object()


class ModuleGroup:
    def __init__(self, name: str, *modules: str):
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_modules", tuple(import_module(m) for m in modules))
        # attr -> [(module, value before the first patch, or _MISSING)]
        object.__setattr__(self, "_originals", {})

    def __repr__(self) -> str:
        return f"<ModuleGroup {self._name}: {len(self._modules)} modules>"

    def __getattr__(self, attr: str) -> Any:
        for module in self._modules:
            if attr in vars(module):
                return vars(module)[attr]
        raise AttributeError(f"none of the modules that replaced '{self._name}' has '{attr}'")

    def __setattr__(self, attr: str, value: Any) -> None:
        holders = [m for m in self._modules if attr in vars(m)] or [self._modules[0]]
        saved = self._originals.setdefault(attr, [(m, vars(m).get(attr, _MISSING)) for m in holders])
        for module in holders:
            setattr(module, attr, value)
        # Setting every module back to what it held is an undo, not a patch.
        if all(original is value for _module, original in saved):
            del self._originals[attr]

    def __delattr__(self, attr: str) -> None:
        """Undo a patch. pytest's monkeypatch undoes one either by setting the old
        value back or by deleting the attribute, depending on its version; a
        delete must put every module's own value back, never remove it."""
        for module, original in self._originals.pop(attr, ()):
            if original is _MISSING:
                vars(module).pop(attr, None)
            else:
                setattr(module, attr, original)


jobs = ModuleGroup(
    "jobs",
    "dpdpcms_py.extensions.breach.sweeps",
    "dpdpcms_py.extensions.reports.sweeps",
    "dpdpcms_py.modules.administration.sweeps",
    "dpdpcms_py.modules.audit_logging.archive",
    "dpdpcms_py.modules.consent_lifecycle.sweeps",
    "dpdpcms_py.modules.grievance.sweeps",
    "dpdpcms_py.modules.notifications.dpo_notify",
    "dpdpcms_py.modules.notifications.sweeps",
    "dpdpcms_py.modules.user_dashboard.sweeps",
)
admin = ModuleGroup(
    "admin",
    "dpdpcms_py.modules.administration.auth",
    "dpdpcms_py.modules.administration.identity",
    "dpdpcms_py.modules.administration.metrics",
    "dpdpcms_py.modules.administration.mfa",
    "dpdpcms_py.modules.administration.operators",
    "dpdpcms_py.modules.administration.setup",
)
catalog = ModuleGroup(
    "catalog",
    "dpdpcms_py.modules.administration.tenancy",
    "dpdpcms_py.modules.consent_lifecycle.notice",
    "dpdpcms_py.modules.consent_lifecycle.policy_store",
)
compliance = ModuleGroup(
    "compliance",
    "dpdpcms_py.extensions.breach.service",
    "dpdpcms_py.modules.consent_lifecycle.erasure",
    "dpdpcms_py.modules.grievance.attachments",
    "dpdpcms_py.modules.grievance.common",
    "dpdpcms_py.modules.grievance.complaints",
    "dpdpcms_py.modules.grievance.resolution",
    "dpdpcms_py.modules.grievance.service",
)
consent = ModuleGroup(
    "consent",
    "dpdpcms_py.modules.consent_lifecycle.collection",
    "dpdpcms_py.modules.consent_lifecycle.common",
    "dpdpcms_py.modules.consent_lifecycle.guardian",
    "dpdpcms_py.modules.consent_lifecycle.history",
    "dpdpcms_py.modules.consent_lifecycle.records",
    "dpdpcms_py.modules.consent_lifecycle.service",
    "dpdpcms_py.modules.consent_lifecycle.validation",
    "dpdpcms_py.modules.consent_lifecycle.wallet",
    "dpdpcms_py.modules.consent_lifecycle.withdrawal",
    "dpdpcms_py.modules.user_dashboard.session",
)
governance = ModuleGroup(
    "governance",
    "dpdpcms_py.extensions.certificates.service",
    "dpdpcms_py.extensions.reports.service",
    "dpdpcms_py.extensions.ropa.service",
    "dpdpcms_py.modules.administration.api_keys",
    "dpdpcms_py.modules.audit_logging.service",
    "dpdpcms_py.modules.notifications.service",
)
lifecycle = ModuleGroup(
    "lifecycle",
    "dpdpcms_py.modules.consent_lifecycle.purpose_lifecycle",
    "dpdpcms_py.modules.notifications.alert_store",
)
rights = ModuleGroup(
    "rights",
    "dpdpcms_py.modules.user_dashboard.nominations",
    "dpdpcms_py.modules.user_dashboard.rights",
)
