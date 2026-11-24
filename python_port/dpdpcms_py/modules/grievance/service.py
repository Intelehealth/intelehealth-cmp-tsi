from __future__ import annotations

from dpdpcms_py.kernel.service import (
    Service,
)
from dpdpcms_py.modules.grievance.attachments import AttachmentHandlers
from dpdpcms_py.modules.grievance.complaints import ComplaintHandlers
from dpdpcms_py.modules.grievance.resolution import ResolutionHandlers
from dpdpcms_py.modules.grievance.routing import RoutingHandlers


class GrievanceService(ComplaintHandlers, AttachmentHandlers, ResolutionHandlers, RoutingHandlers, Service):
    pass
