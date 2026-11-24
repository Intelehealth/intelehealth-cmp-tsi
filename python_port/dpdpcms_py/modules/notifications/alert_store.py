from __future__ import annotations

import logging

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.modules.audit_logging.ledger import log_event

log = logging.getLogger("dpdpcms.lifecycle")


def record_alert(
    fiduciary_id: str,
    alert_type: str,
    event_ref_id: str | None = None,
    payload: dict | None = None,
    *,
    recipient_type: str = "FIDUCIARY",
    recipient_id: str | None = None,
) -> str | None:
    """Insert an alert row (NT-06): for the fiduciary by default, or for one
    PROCESSOR app (CW-08). Used by close_purpose, withdrawal and the alert API."""
    if not fiduciary_id or not alert_type:
        return None
    try:
        row = db.insert_returning(
            f"""
            INSERT INTO alerts (fiduciary_id, recipient_type, recipient_id_enc, recipient_id_hmac, alert_type,
                                event_ref_id, payload)
            VALUES (%s, %s, {pii.PID_VALUES}, %s, %s, %s)
            RETURNING id
            """,
            (
                str(fiduciary_id),
                recipient_type,
                *pii.pid_params(str(recipient_id or fiduciary_id)),
                alert_type,
                event_ref_id,
                # P16-03: principal ids in the payload are sealed at rest.
                db.as_jsonb(pii.seal_principal_keys(payload or {})),
            ),
        )
    except Exception as exc:
        # Type and SQLSTATE only: a driver message can quote the failing row,
        # principal id included.
        log.error(
            "Could not record %s alert for fiduciary %s: %s (sqlstate %s)",
            alert_type,
            fiduciary_id,
            type(exc).__name__,
            getattr(exc, "sqlstate", None),
        )
        return None
    alert_id = str(row["id"]) if row else None
    # NT-10: every alert is recorded in the audit log, not only the ones raised
    # through the alerts API. Payload keys only — it may carry a user_id.
    try:
        log_event(
            "SYSTEM",
            str(fiduciary_id),
            "SYSTEM",
            None,
            "ALERT_RAISED",
            {
                "alert_id": alert_id,
                "alert_type": alert_type,
                "recipient_type": recipient_type,
                "recipient_id": str(recipient_id) if recipient_id else None,
                "event_ref_id": str(event_ref_id) if event_ref_id else None,
                "purpose_id": (payload or {}).get("purpose_id"),
            },
        )
    except Exception:  # pragma: no cover - auditing must not lose the alert
        pass
    return alert_id


def notify_processors(
    fiduciary_id: str,
    alert_type: str,
    event_ref_id: str | None,
    payload: dict,
    category: str = "NOTIFICATION",
) -> list[str]:
    """CW-08: every linked processor hears about a withdrawal, an erasure or a
    purpose closure on its own endpoint, and gets its own acknowledgeable
    PROCESSOR alert - one endpoint per category no longer stands in for all of
    them. Returns the processor app ids notified."""
    from dpdpcms_py.modules.notifications.webhooks import fan_out_to_processors

    try:
        apps = fan_out_to_processors(fiduciary_id, alert_type, payload, category=category)
    except Exception:  # pragma: no cover - a fan-out failure never undoes the action
        return []
    for app_id in apps:
        record_alert(fiduciary_id, alert_type, event_ref_id, payload, recipient_type="PROCESSOR", recipient_id=app_id)
    return apps
