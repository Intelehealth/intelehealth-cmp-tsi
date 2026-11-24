from __future__ import annotations

from dpdpcms_py.kernel.registry import Module, Sweep

from . import archive, ledger
from .service import AuditService

MODULE = Module(
    name="audit_logging",
    title="Logging",
    submodules=("Audit Logs",),
    requirement_prefixes=("LG",),
    services={"audit": AuditService},
    sweeps={
        "audit_chain": Sweep(ledger.record_chain_verification, "P6-12 daily full-ledger verification"),
        "legacy_ledger": Sweep(ledger.verify_legacy_ledger, "P16-02 sealed pre-db/32 ledger, weekly"),
        "audit_partitions": Sweep(
            archive.archive_audit_partitions, "yearly audit partitions; archive beyond AUDIT_LIVE_YEARS"
        ),
    },
    tables=(
        "audit_logs",
        "audit_chain_verifications",
        "audit_log_archive_registry",
        "audit_legacy_ledger_seal",
        "audit_legacy_ledger_verifications",
    ),
    notes="The one module every other module may import: each of them writes to the ledger.",
)
