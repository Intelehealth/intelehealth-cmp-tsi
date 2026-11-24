from __future__ import annotations

from dpdpcms_py.kernel.service import Service
from dpdpcms_py.modules.user_dashboard.corrections import CorrectionHandlers
from dpdpcms_py.modules.user_dashboard.nominations import NominationHandlers


class RightsService(NominationHandlers, CorrectionHandlers, Service):
    """Data Principal rights not covered by the consent/grievance flow.

    Implements the DPDP right to nominate (Section 15) and the right to request
    correction of personal data.
    """
