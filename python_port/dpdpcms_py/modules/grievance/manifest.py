from __future__ import annotations

from dpdpcms_py.kernel.registry import Module, Sweep

from . import sweeps
from .service import GrievanceService

MODULE = Module(
    name="grievance",
    title="Grievance Redressal Mechanism",
    submodules=("Complaint Logging", "Resolution Tracking"),
    requirement_prefixes=("GR",),
    services={"grievance": GrievanceService},
    sweeps={"grievances": Sweep(sweeps.escalate_overdue_grievances, "UD-12, GR-09")},
    tables=("grievances", "grievance_attachments", "grievance_routing_rules"),
)
