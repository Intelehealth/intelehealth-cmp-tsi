from __future__ import annotations

from dpdpcms_py.kernel.service import (
    Service,
)
from dpdpcms_py.modules.consent_lifecycle.collection import CollectionHandlers
from dpdpcms_py.modules.consent_lifecycle.guardian import GuardianHandlers
from dpdpcms_py.modules.consent_lifecycle.history import HistoryHandlers
from dpdpcms_py.modules.consent_lifecycle.records import RecordHandlers
from dpdpcms_py.modules.consent_lifecycle.validation import ValidationHandlers
from dpdpcms_py.modules.consent_lifecycle.withdrawal import WithdrawalHandlers


class ConsentService(
    CollectionHandlers,
    GuardianHandlers,
    ValidationHandlers,
    WithdrawalHandlers,
    RecordHandlers,
    HistoryHandlers,
    Service,
):
    pass
