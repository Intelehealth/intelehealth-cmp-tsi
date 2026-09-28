from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from . import db
from .config import settings
from .defaults import DEFAULT_NOTIFICATION_MESSAGES
from .netutil import post_json

log = logging.getLogger("dpdpcms.delivery")

CHANNELS = ("IN_APP", "EMAIL", "SMS", "PUSH")


def render_message(fiduciary_id: str, notification_type: str, recipient_type: str) -> tuple[str, str]:
    """Return (subject, body) for a notification type.

    Uses the DPO-configured template (notification_message_templates), falling
    back to the built-in English defaults. Message lookup is live — editing the
    template changes how newly delivered notifications read.
    """
    fallback = DEFAULT_NOTIFICATION_MESSAGES.get(notification_type, {}).get("en") or notification_type
    template = db.one(
        "SELECT messages FROM notification_message_templates WHERE fiduciary_id = %s AND notification_type = %s",
        (fiduciary_id, notification_type),
    )
    if template:
        messages = template.get("messages") or {}
        if isinstance(messages, dict) and messages.get("en"):
            fallback = str(messages["en"])
    return f"TSI DPDP CMS — {notification_type}", fallback


def _enqueue(notification_id: str, channel: str, recipient: str | None, status: str = "PENDING") -> None:
    db.execute(
        """
        INSERT INTO notification_deliveries (notification_id, channel, recipient, status, created_at)
        VALUES (%s, %s, %s, %s, NOW())
        """,
        (notification_id, channel, recipient, status),
    )


def _recipient_email(recipient_type: str, recipient_id: str) -> str | None:
    """Resolve a delivery address for a non-principal recipient from encrypted columns."""
    col = "(SELECT pgp_sym_decrypt(decode(%s, 'base64'), %s))"
    if recipient_type in {"DPO", "ADMIN", "OPERATOR"}:
        row = db.one(
            f"SELECT {col} AS email FROM operators WHERE id = %s AND email_enc IS NOT NULL",
            (settings.db_encryption_key, settings.db_encryption_key, recipient_id),
        )
        return str(row["email"]) if row and row.get("email") else None
    for table, id_column in (("fiduciaries", "id"), ("apps", "id")):
        try:
            row = db.one(
                f"SELECT {col} AS email FROM {table} WHERE {id_column} = %s AND email_enc IS NOT NULL",
                (settings.db_encryption_key, settings.db_encryption_key, recipient_id),
            )
        except Exception:
            continue
        if row and row.get("email"):
            return str(row["email"])
    return None


def _backfill_deliveries(limit: int) -> int:
    """Create delivery rows for notifications that do not have any yet.

    In-app delivery is an immediate success (the notifications row is the in-app
    artifact). EMAIL / SMS / PUSH rows are created only when the corresponding
    channel is configured, so an unconfigured channel never silently claims a
    notification was delivered.
    """
    rows = db.all(
        """
        SELECT n.id, n.recipient_type, n.recipient_id, n.fiduciary_id, n.notification_type
        FROM notifications n
        LEFT JOIN notification_deliveries d ON d.notification_id = n.id
        WHERE d.id IS NULL
        ORDER BY n.created_at
        LIMIT %s
        """,
        (limit,),
    )
    count = 0
    for row in rows:
        nid = str(row["id"])
        recipient_type = str(row["recipient_type"] or "").upper()
        recipient_id = str(row["recipient_id"] or "")
        _enqueue(nid, "IN_APP", recipient_id, status="SENT")
        count += 1
        if settings.smtp_host and recipient_type not in {"PRINCIPAL"}:
            email = _recipient_email(recipient_type, recipient_id)
            if email:
                _enqueue(nid, "EMAIL", email)
                count += 1
        if settings.sms_gateway_url and recipient_type == "PRINCIPAL":
            _enqueue(nid, "SMS", recipient_id)
            count += 1
        if settings.push_gateway_url:
            _enqueue(nid, "PUSH", recipient_id)
            count += 1
    return count


def _deliver_email(delivery_id: str, recipient: str, subject: str, body: str) -> tuple[str | None, str | None]:
    """Send via SMTP. Returns (error, sent_at note)."""
    if not settings.smtp_host:
        return "SMTP not configured", None
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from or settings.smtp_username
    message["To"] = recipient
    message.set_content(body)
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30) as server:
            if settings.smtp_starttls:
                server.starttls()
            if settings.smtp_username:
                server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(message)
        return None, None
    except Exception as exc:  # noqa: BLE001 - any SMTP failure is a delivery failure
        log.warning("Email delivery %s failed: %s", delivery_id, exc)
        return str(exc), None


def _deliver_gateway(channel: str, recipient_id: str, body: str) -> tuple[str | None, str | None]:
    url = settings.sms_gateway_url if channel == "SMS" else settings.push_gateway_url
    if not url:
        return f"{channel} gateway not configured", None
    try:
        status, response = post_json(url, {"channel": channel, "recipient_id": recipient_id, "message": body}, timeout=20)
        if status is None:
            return f"{channel} gateway unreachable: {response}", None
        if status >= 400:
            return f"{channel} gateway HTTP {status}: {response[:200]}", None
        return None, None
    except Exception as exc:  # noqa: BLE001
        return f"{channel} gateway error: {exc}", None


def _reclaim_stale_processing() -> None:
    db.execute(
        """
        UPDATE notification_deliveries
        SET status = 'PENDING'
        WHERE status = 'PROCESSING'
          AND last_attempt_at IS NOT NULL
          AND last_attempt_at < NOW() - INTERVAL '30 minutes'
        """
    )


def _claim_delivery(delivery_id: str) -> bool:
    return (
        db.execute(
            """
            UPDATE notification_deliveries
            SET status = 'PROCESSING', last_attempt_at = NOW()
            WHERE id = %s AND status = 'PENDING'
            """,
            (delivery_id,),
        )
        == 1
    )


def _deliver_pending(limit: int) -> dict[str, int]:
    _reclaim_stale_processing()
    rows = db.all(
        """
        SELECT d.id, d.notification_id, d.channel, d.recipient, d.attempt_count,
               n.fiduciary_id, n.notification_type, n.recipient_type, n.recipient_id
        FROM notification_deliveries d
        JOIN notifications n ON n.id = d.notification_id
        WHERE d.status = 'PENDING'
        ORDER BY d.created_at
        LIMIT %s
        """,
        (limit,),
    )
    sent = failed = skipped = 0
    for row in rows:
        delivery_id = str(row["id"])
        if not _claim_delivery(delivery_id):
            continue
        channel = str(row["channel"] or "").upper()
        attempt = int(row["attempt_count"] or 0) + 1
        fid = str(row["fiduciary_id"]) if row.get("fiduciary_id") else ""
        subject, body = render_message(fid, row["notification_type"], row["recipient_type"])
        error: str | None
        if channel == "IN_APP":
            error, _ = None, None
            status = "SENT" if error is None else "FAILED"
            db.execute(
                "UPDATE notification_deliveries SET status = %s, attempt_count = %s, last_attempt_at = NOW(), sent_at = NOW(), last_error = NULL WHERE id = %s",
                (status, attempt, delivery_id),
            )
            sent += 1
            continue
        if channel == "EMAIL":
            error, _ = _deliver_email(delivery_id, row["recipient"] or "", subject, body)
        elif channel in {"SMS", "PUSH"}:
            error, _ = _deliver_gateway(channel, row["recipient"] or row["recipient_id"] or "", body)
        else:
            error = f"Unknown channel {channel}"
        if error is None:
            db.execute(
                "UPDATE notification_deliveries SET status = 'SENT', attempt_count = %s, last_attempt_at = NOW(), sent_at = NOW(), last_error = NULL WHERE id = %s",
                (attempt, delivery_id),
            )
            sent += 1
        elif channel not in {"EMAIL", "SMS", "PUSH"}:
            db.execute(
                "UPDATE notification_deliveries SET status = 'SKIPPED', attempt_count = %s, last_attempt_at = NOW(), last_error = %s WHERE id = %s",
                (attempt, error, delivery_id),
            )
            skipped += 1
        elif attempt >= settings.notification_retry_limit:
            db.execute(
                "UPDATE notification_deliveries SET status = 'FAILED', attempt_count = %s, last_attempt_at = NOW(), last_error = %s WHERE id = %s",
                (attempt, error, delivery_id),
            )
            failed += 1
        else:
            db.execute(
                "UPDATE notification_deliveries SET status = 'PENDING', attempt_count = %s, last_attempt_at = NOW(), last_error = %s WHERE id = %s",
                (attempt, error, delivery_id),
            )
            failed += 1
    return {"sent": sent, "failed": failed, "skipped": skipped}


def process_pending_notifications(limit: int | None = None) -> dict[str, int]:
    """Backfill and deliver pending notifications. Called by the worker."""
    limit = limit or settings.worker_batch_size
    enqueued = _backfill_deliveries(limit)
    counts = _deliver_pending(limit)
    counts["enqueued"] = enqueued
    return counts