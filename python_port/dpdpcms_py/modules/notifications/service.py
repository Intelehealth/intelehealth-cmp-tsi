from __future__ import annotations

from dpdpcms_py.kernel.service import (
    Service,
)
from dpdpcms_py.modules.notifications.portal_config import PortalConfigHandlers
from dpdpcms_py.modules.notifications.templates import TemplateHandlers
from dpdpcms_py.modules.notifications.user import UserNotificationHandlers
from dpdpcms_py.modules.notifications.webhook_config import WebhookConfigHandlers


class NotificationService(
    UserNotificationHandlers, TemplateHandlers, WebhookConfigHandlers, PortalConfigHandlers, Service
):
    pass
