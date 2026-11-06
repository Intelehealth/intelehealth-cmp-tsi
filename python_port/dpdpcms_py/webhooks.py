from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime
from typing import Any

from . import db, pii
from .config import settings
from .netutil import post_json

log = logging.getLogger("dpdpcms.webhooks")

SIGNATURE_HEADER = "X-TSI-Signature"
DEFAULT_CATEGORY = "NOTIFICATION"


def queue_webhook(
    fiduciary_id: str,
    event_type: str,
    payload: dict[str, Any],
    category: str = DEFAULT_CATEGORY,
    app_id: str | None = None,
) -> None:
    """Record an outbound webhook event for the dispatcher worker to deliver.

    The event is queued here (inline on the request thread) and delivered
    asynchronously by the worker. Delivery failures are retried up to the
    configured limit without blocking the API call that raised the event.
    `app_id` addresses the event to one processor's own endpoint (CW-08)
    instead of the fiduciary's. Principal ids in the payload are sealed at rest
    (P16-03) and opened only by the dispatcher, immediately before the POST.
    """
    if not fiduciary_id or not event_type:
        return
    try:
        sealed = pii.seal_principal_keys(payload)
        db.execute(
            """
            INSERT INTO webhook_deliveries (fiduciary_id, category, event_type, payload, app_id)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (str(fiduciary_id), category or DEFAULT_CATEGORY, event_type, db.as_jsonb(sealed), app_id),
        )
    except Exception:
        # A failed webhook queue must never break the consent action that
        # produced the event. The event is still reachable through audit.
        log.exception("Failed to queue webhook event %s for %s", event_type, fiduciary_id)


def linked_processors(fiduciary_id: str, category: str = DEFAULT_CATEGORY) -> list[str]:
    """CW-08 / P11-05: the processors acting for a fiduciary on this class of event.

    A processor is an ACTIVE app that has registered an enabled endpoint for
    the category (processor_webhook_configs) and carries a recorded processing
    agreement (dpa_reference). Every other app - an integrator key with no
    endpoint and no role in the processing - is not sent the principal's
    identifier and gets no alert it could never acknowledge.
    """
    try:
        rows = db.all(
            """
            SELECT a.id
            FROM apps a
            JOIN processor_webhook_configs p ON p.app_id = a.id AND p.fiduciary_id = a.fiduciary_id
            WHERE a.fiduciary_id = %s AND a.status = 'ACTIVE'
              AND p.category = %s AND p.enabled IS TRUE
              AND btrim(COALESCE(a.dpa_reference, '')) <> ''
            ORDER BY a.id
            """,
            (str(fiduciary_id), category or DEFAULT_CATEGORY),
        )
    except Exception:
        log.exception("Could not list processors for %s", fiduciary_id)
        return []
    return [str(row["id"]) for row in rows]


def fan_out_to_processors(
    fiduciary_id: str, event_type: str, payload: dict[str, Any], category: str = DEFAULT_CATEGORY
) -> list[str]:
    """CW-08: tell every linked processor, not only the fiduciary.

    One delivery per processor, addressed to that processor's own endpoint
    (processor_webhook_configs). P11-05: only apps registered as processors
    for the category are addressed - see linked_processors. Returns the
    processor app ids notified.
    """
    apps = linked_processors(fiduciary_id, category)
    for app_id in apps:
        queue_webhook(fiduciary_id, event_type, payload, category=category, app_id=app_id)
    return apps


def _decrypt_secret(secret_enc: str | None) -> str:
    if not settings.db_encryption_key or not secret_enc:
        return ""
    try:
        row = db.one(
            "SELECT pgp_sym_decrypt(decode(%s, 'base64'), %s) AS secret",
            (secret_enc, settings.db_encryption_key),
        )
    except Exception:
        return ""
    return str(row["secret"]) if row else ""


def _sign(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _render_otp(payload: dict[str, Any]) -> dict[str, Any]:
    """Render a queued OTP webhook into its outbound payload (SEC-13).

    The queue stores the code encrypted (principal_otp.encrypt_code) and the
    unrendered template; the plaintext is materialised only here, in memory,
    immediately before the POST, so the database row never holds it.
    """
    if not payload.get("otp_enc"):
        return payload
    from . import principal_otp

    code = principal_otp.decrypt_code(payload.get("otp_enc"))
    out = {k: v for k, v in payload.items() if k not in {"otp_enc", "message_template"}}
    if code is None:
        out["error"] = "otp_enc could not be decrypted"
        out["otp"] = None
        return out
    template = payload.get("message_template") or "Your verification code is {{otp}}"
    out["otp"] = code
    out["message"] = template.replace("{{otp}}", code)
    return out


def _send(delivery: dict[str, Any], config: dict[str, Any]) -> tuple[int | None, str | None]:
    """POST one queued delivery to one webhook config. Returns (status, error)."""
    payload = _render_otp(pii.open_principal_keys([delivery.get("payload") or {}])[0])
    envelope = {
        "event_id": str(delivery["id"]),
        "event_type": delivery["event_type"],
        "occurred_at": datetime.now(UTC).isoformat(),
        "data": payload,
    }
    body = json.dumps(envelope, default=str).encode("utf-8")
    url = config["webhook_url"]
    headers: dict[str, str] = {"X-TSI-Event-Id": str(delivery["id"])}
    if config["secret"]:
        headers[SIGNATURE_HEADER] = _sign(config["secret"], body)
    try:
        status, response = post_json(url, json.loads(body), headers, timeout=15)
    except (ValueError, OSError) as exc:
        # CC-09/CU-08: the send-time SSRF/DNS check raises before any connection
        # is made. That is a failed attempt for this config, never a reason to
        # abort the sweep and strand the delivery in PROCESSING.
        log.warning("Webhook %s to %s refused: %s", delivery["id"], url, exc)
        return None, f"refused: {exc}"
    if status is None:
        return None, response
    if status >= 400:
        return status, f"HTTP {status}: {response[:200]}"
    return status, None


def process_pending_webhooks(limit: int | None = None) -> dict[str, int]:
    """Deliver queued webhook events. Returns a summary dict.

    Called by the background worker every poll cycle. Each run claims a batch of
    PENDING deliveries and dispatches them to every enabled webhook config for
    the fiduciary, signing the body with the per-config shared secret. SSRF
    validation runs at save time (set_webhook_config) and again at send time.
    """
    limit = limit or settings.worker_batch_size
    db.execute(
        """
        UPDATE webhook_deliveries
        SET status = 'PENDING'
        WHERE status = 'PROCESSING'
          AND last_dispatched_at IS NOT NULL
          AND last_dispatched_at < NOW() - INTERVAL '30 minutes'
        """
    )
    deliveries = db.all(
        """
        SELECT id, fiduciary_id, category, event_type, payload, attempt_count, app_id
        FROM webhook_deliveries
        WHERE status = 'PENDING'
        ORDER BY created_at
        LIMIT %s
        """,
        (limit,),
    )
    result = {"dispatched": 0, "failed": 0, "skipped": 0}
    for delivery in deliveries:
        delivery_id = str(delivery["id"])
        if (
            db.execute(
                """
                UPDATE webhook_deliveries
                SET status = 'PROCESSING', last_dispatched_at = NOW()
                WHERE id = %s AND status = 'PENDING'
                """,
                (delivery_id,),
            )
            != 1
        ):
            continue
        fid = str(delivery["fiduciary_id"])
        category = delivery["category"] or DEFAULT_CATEGORY
        if delivery.get("app_id"):
            # CW-08: a processor-addressed event goes to that processor's own
            # endpoint only - never to the fiduciary's or another processor's.
            configs = db.all(
                """
                SELECT fiduciary_id, category, webhook_url, secret_enc, enabled
                FROM processor_webhook_configs
                WHERE fiduciary_id = %s AND app_id = %s AND category = %s AND enabled IS TRUE
                """,
                (fid, str(delivery["app_id"]), category),
            )
        else:
            configs = db.all(
                """
                SELECT fiduciary_id, category, webhook_url, secret_enc, enabled
                FROM webhook_configs
                WHERE fiduciary_id = %s AND category = %s AND enabled IS TRUE
                """,
                (fid, category),
            )
        if not configs:
            # No enabled webhook for this event — nothing to deliver.
            db.execute("UPDATE webhook_deliveries SET status = 'SKIPPED' WHERE id = %s", (delivery_id,))
            result["skipped"] += 1
            continue
        attempt = int(delivery["attempt_count"] or 0) + 1
        delivered = False
        last_error = None
        for config in configs:
            status, error = _send(
                {**delivery, "id": delivery_id},
                {"webhook_url": config["webhook_url"], "secret": _decrypt_secret(config.get("secret_enc"))},
            )
            if status is not None and status < 400:
                delivered = True
                last_error = None
                last_status = status
                break
            last_error = error
            last_status = status
        if delivered:
            db.execute(
                "UPDATE webhook_deliveries SET status = 'DISPATCHED', attempt_count = %s, last_dispatched_at = NOW(), dispatched_at = NOW(), response_status_code = %s, last_error = NULL WHERE id = %s",
                (attempt, last_status, delivery_id),
            )
            result["dispatched"] += 1
        elif attempt >= settings.webhook_retry_limit:
            db.execute(
                "UPDATE webhook_deliveries SET status = 'FAILED', attempt_count = %s, last_dispatched_at = NOW(), last_error = %s WHERE id = %s",
                (attempt, last_error, delivery_id),
            )
            result["failed"] += 1
        else:
            db.execute(
                """
                UPDATE webhook_deliveries
                SET status = 'PENDING', attempt_count = %s, last_dispatched_at = NOW(), last_error = %s
                WHERE id = %s
                """,
                (attempt, last_error, delivery_id),
            )
            result["failed"] += 1
    return result
