from __future__ import annotations

from .admin import AdminDashService, AdminSetupService, OperatorService
from .catalog import AppService, FiduciaryService, PolicyService
from .compliance import BreachService, ComplianceService, GrievanceService
from .consent import ConsentService, PrincipalService, WalletService
from .governance import ApiKeyService, AuditService, JobService, LegalService, NotificationService, RopaService

SERVICE_REGISTRY = {
    "setup": AdminSetupService,
    "operator": OperatorService,
    "admindash": AdminDashService,
    "fiduciary": FiduciaryService,
    "app": AppService,
    "apikey": ApiKeyService,
    "policy": PolicyService,
    "consent": ConsentService,
    "principal": PrincipalService,
    "wallet": WalletService,
    "compliance": ComplianceService,
    "grievance": GrievanceService,
    "notification": NotificationService,
    "audit": AuditService,
    "job": JobService,
    "ropa": RopaService,
    "legal": LegalService,
    "breach": BreachService,
}
