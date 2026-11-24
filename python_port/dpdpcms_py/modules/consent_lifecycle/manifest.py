from __future__ import annotations

from dpdpcms_py.kernel.registry import Module, Sweep

from . import policy_store, sweeps
from .erasure import ComplianceService
from .notice import PolicyService
from .purpose_lifecycle import PurposeLifecycleService
from .service import ConsentService
from .wallet import WalletService

MODULE = Module(
    name="consent_lifecycle",
    title="Consent Management Lifecycle",
    submodules=(
        "Consent Collection",
        "Consent Validation",
        "Consent Update",
        "Consent Renewal",
        "Consent Withdrawal",
    ),
    requirement_prefixes=("CC", "CV", "CU", "PL", "CW"),
    services={
        "policy": PolicyService,
        "consent": ConsentService,
        "wallet": WalletService,
        "compliance": ComplianceService,
        "purpose": PurposeLifecycleService,
    },
    sweeps={
        "time_bound_purposes": Sweep(sweeps.close_due_time_bound_purposes, "PL-01 time-bound closure"),
        "superseded_policies": Sweep(policy_store.retire_all_superseded_versions, "CU-05 superseded notice versions"),
        "overdue_purges": Sweep(sweeps.flag_overdue_purges, "SA-09 unconfirmed purges"),
    },
    tables=(
        "consent_records",
        "consent_policies",
        "data_principal",
        "parental_verification_logs",
        "consent_validations",
        "reconsent_requests",
        "purpose_lifecycle",
        "purge_requests",
    ),
    notes=(
        "Consent Renewal is not applicable (DPO decision DD-01: consent is open-ended); "
        "purpose_lifecycle.py is the recorded substitute (PL-01 to PL-04)."
    ),
)
