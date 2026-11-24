from __future__ import annotations

from dpdpcms_py.kernel.registry import Module, Sweep

from . import sweeps
from .rights import RightsService
from .session import PrincipalService

MODULE = Module(
    name="user_dashboard",
    title="User Dashboard",
    submodules=("View Consent History", "Modify or Revoke Consent", "Raise Grievances or Data Requests"),
    requirement_prefixes=("UD",),
    services={"principal": PrincipalService, "rights": RightsService},
    sweeps={"nominations": Sweep(sweeps.expire_nominations, "P6-07 nomination window expiry")},
    tables=("principal_otps", "data_correction_requests", "nominations"),
    notes=(
        "A URL service belongs to one module, so the dashboard's history and revoke calls are "
        "served by consent_lifecycle (service 'consent') and its complaint form by grievance."
    ),
)
