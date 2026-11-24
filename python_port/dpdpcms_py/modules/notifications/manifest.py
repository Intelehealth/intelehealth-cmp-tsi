from __future__ import annotations

from dpdpcms_py.kernel.registry import Module, Sweep

from . import delivery, sweeps, webhooks
from .alerts import AlertService
from .service import NotificationService

MODULE = Module(
    name="notifications",
    title="Consent Notifications",
    submodules=("User Notifications", "Data Fiduciary and Processor Alerts"),
    requirement_prefixes=("NT",),
    services={"notification": NotificationService, "alerts": AlertService},
    sweeps={
        "delivery": Sweep(delivery.process_pending_notifications, "NT-04 delivery adapter"),
        "webhooks": Sweep(webhooks.process_pending_webhooks, "CC-09/CU-08/CW-08 dispatcher"),
        "alerts": Sweep(sweeps.escalate_stale_alerts, "NT-09"),
        "webhook_deliveries": Sweep(sweeps.prune_old_webhook_deliveries, "SEC-13/P5-07 webhook retention"),
        "notification_deliveries": Sweep(
            sweeps.prune_old_notification_deliveries, "SA-13 notification delivery retention"
        ),
        "sealed_payloads": Sweep(sweeps.seal_queued_payloads, "P16-03 principal ids in queued payloads sealed"),
    },
    tables=(
        "notifications",
        "notification_deliveries",
        "notification_message_templates",
        "notification_message_templates_archive",
        "alerts",
        "webhook_configs",
        "processor_webhook_configs",
        "webhook_deliveries",
        "rights_app_config",
    ),
)
