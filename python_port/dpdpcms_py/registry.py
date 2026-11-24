"""The service registry and the worker's sweep table, assembled from manifests.

Each package under `modules/` (one per BRD module) and `extensions/` declares
its own services, sweeps and tables in `manifest.py`. This file only puts them
in order: SERVICE_ORDER and SWEEP_ORDER are the orders the dispatcher, the
generated OpenAPI documents and the worker heartbeat have always used.
"""

from __future__ import annotations

from dpdpcms_py.extensions.breach.manifest import MODULE as breach
from dpdpcms_py.extensions.certificates.manifest import MODULE as certificates
from dpdpcms_py.extensions.reports.manifest import MODULE as reports
from dpdpcms_py.extensions.ropa.manifest import MODULE as ropa
from dpdpcms_py.kernel.registry import Module, Sweep
from dpdpcms_py.modules.administration.manifest import MODULE as administration
from dpdpcms_py.modules.audit_logging.manifest import MODULE as audit_logging
from dpdpcms_py.modules.consent_lifecycle.manifest import MODULE as consent_lifecycle
from dpdpcms_py.modules.cookie_consent.manifest import MODULE as cookie_consent
from dpdpcms_py.modules.grievance.manifest import MODULE as grievance
from dpdpcms_py.modules.notifications.manifest import MODULE as notifications
from dpdpcms_py.modules.user_dashboard.manifest import MODULE as user_dashboard

# The seven modules of the MeitY/NeGD BRD, in the BRD's order.
BRD_MODULES: tuple[Module, ...] = (
    consent_lifecycle,
    cookie_consent,
    user_dashboard,
    notifications,
    grievance,
    administration,
    audit_logging,
)
# Required by the DPDP Act and Rules, or by operations, but not named in the BRD.
EXTENSIONS: tuple[Module, ...] = (breach, ropa, certificates, reports)
MODULES: tuple[Module, ...] = BRD_MODULES + EXTENSIONS

SERVICE_ORDER = (
    "setup",
    "operator",
    "admindash",
    "fiduciary",
    "app",
    "apikey",
    "policy",
    "consent",
    "principal",
    "wallet",
    "compliance",
    "grievance",
    "notification",
    "audit",
    "job",
    "ropa",
    "legal",
    "breach",
    "rights",
    "alerts",
    "purpose",
    "retention",
    "role",
    "pii",
)
SWEEP_ORDER = (
    "delivery",
    "webhooks",
    "time_bound_purposes",
    "superseded_policies",
    "alerts",
    "grievances",
    "retention",
    "jobs",
    "overdue_purges",
    "legal_holds",
    "revoked_tokens",
    "expired_api_keys",
    "throttles",
    "sso_nonces",
    "nominations",
    "webhook_deliveries",
    "notification_deliveries",
    "audit_chain",
    "legacy_ledger",
    "sealed_payloads",
    "audit_partitions",
    "security_monitor",
    "breach_deadlines",
)


def _collect(attribute: str, order: tuple[str, ...]) -> dict:
    found: dict = {}
    owner: dict[str, str] = {}
    for module in MODULES:
        for name, value in getattr(module, attribute).items():
            if name in found:
                raise RuntimeError(f"{attribute} '{name}' is declared by both {owner[name]} and {module.name}")
            found[name], owner[name] = value, module.name
    if set(found) != set(order):
        raise RuntimeError(
            f"{attribute} order is out of step with the manifests: "
            f"unlisted {sorted(set(found) - set(order))}, undeclared {sorted(set(order) - set(found))}"
        )
    return {name: found[name] for name in order}


SERVICE_REGISTRY: dict[str, type] = _collect("services", SERVICE_ORDER)
SWEEPS: dict[str, Sweep] = _collect("sweeps", SWEEP_ORDER)
SERVICE_MODULE: dict[str, str] = {name: m.name for m in MODULES for name in m.services}
TABLE_OWNER: dict[str, str] = {table: m.name for m in MODULES for table in m.tables}
