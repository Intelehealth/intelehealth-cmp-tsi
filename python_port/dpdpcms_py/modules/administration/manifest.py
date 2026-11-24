from __future__ import annotations

from dpdpcms_py.kernel import throttle
from dpdpcms_py.kernel.registry import Module, Sweep

from . import sweeps
from .api_keys import ApiKeyService
from .metrics import AdminDashService
from .operators import OperatorService
from .pii_reveal import PiiService
from .retention import RetentionService
from .roles import RoleService
from .setup import AdminSetupService
from .tenancy import AppService, FiduciaryService

MODULE = Module(
    name="administration",
    title="System Administration",
    submodules=("User Role Management", "Data Retention Policy Configuration"),
    requirement_prefixes=("SA",),
    services={
        "setup": AdminSetupService,
        "operator": OperatorService,
        "admindash": AdminDashService,
        "fiduciary": FiduciaryService,
        "app": AppService,
        "apikey": ApiKeyService,
        "retention": RetentionService,
        "role": RoleService,
        "pii": PiiService,
    },
    sweeps={
        "retention": Sweep(sweeps.run_retention_sweep, "PL-04/SA-09, SA-11"),
        "legal_holds": Sweep(sweeps.release_expired_legal_holds, "CW-11 legal hold end"),
        "revoked_tokens": Sweep(sweeps.prune_revoked_tokens, "SA-05 revocation list"),
        "expired_api_keys": Sweep(sweeps.expire_lapsed_api_keys, "SEC-07 expiry enforcement"),
        "throttles": Sweep(throttle.prune_expired, "SEC-01/03 throttle table"),
        "sso_nonces": Sweep(sweeps.prune_sso_nonces, "SEC-14 one-time SSO nonces"),
        "security_monitor": Sweep(sweeps.flag_security_anomalies, "Rule 6(1)(c) failed sign-in bursts, reveal volume"),
    },
    tables=(
        "operators",
        "roles",
        "auth_throttles",
        "sso_login_nonces",
        "revoked_tokens",
        "retention_policies",
        "fiduciaries",
        "apps",
        "api_keys",
        "tsi_reader_tenants",
        "worker_heartbeat",
    ),
    notes="Tenancy (fiduciaries, apps, API keys) is not in the BRD; it is an administrator's job.",
)
