from __future__ import annotations

import logging

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.config import settings
from dpdpcms_py.modules.audit_logging.ledger import log_event

log = logging.getLogger("dpdpcms.jobs")


def escalate_stale_alerts() -> dict[str, int]:
    """NT-09: escalate alerts nobody has acknowledged within the SLA window."""
    rows = db.all(
        """
        UPDATE alerts
        SET status = 'ESCALATED', escalated_at = NOW()
        WHERE status = 'PENDING' AND requires_action IS TRUE
          AND created_at < NOW() - make_interval(hours => %s)
        RETURNING id, fiduciary_id, alert_type
        """,
        (settings.alert_escalation_hours,),
    )
    # NT-10: an escalation is an alert event and is audited like one.
    for row in rows:
        log_event(
            "SYSTEM",
            str(row["fiduciary_id"]),
            "SYSTEM",
            None,
            "ALERT_ESCALATED",
            {"alert_id": str(row["id"]), "alert_type": row.get("alert_type")},
        )
    return {"escalated": len(rows)}


# P5-07: Rule 6(1)(e) sets a ONE-YEAR floor on retaining logs and personal
# data. webhook_deliveries is the channel of record for consent events and OTP
# dispatch, so terminal rows may never be pruned faster than this floor, whatever
# WEBHOOK_DELIVERY_RETENTION_DAYS says. audit_logs and notification_deliveries
# are intentionally NEVER pruned by any sweep — audit_logs is append-only by
# trigger (db/19) and notification_deliveries now has a database-enforced
# one-year DELETE floor (db/23) — which satisfies the same floor by construction;
# that retention choice is stated here as policy, not an accident of the code.
RULE_6_1_E_MIN_RETENTION_DAYS = 365


# P16-03: a payload still holding a principal key in the clear (queued before
# db/37) - a key followed by a non-null value, at any depth.
_PLAIN_PRINCIPAL_KEY = '"(' + "|".join(sorted(pii.PRINCIPAL_KEYS)) + ')": (?!null)'


SEAL_BATCH = 500


def seal_queued_payloads(limit: int = SEAL_BATCH) -> dict[str, int]:
    """P16-03: seal the principal ids of alert and webhook payloads queued before db/37.

    New payloads are sealed when written; this converts older rows in place,
    a batch per table per cycle, and is a no-op once none is left. The
    webhook payload floor (db/37) accepts the change because the sealed value
    decrypts to the value it replaces. A row that cannot be sealed (a
    non-string id the floor cannot compare) is logged and counted.
    """
    out: dict[str, int] = {}
    for table in ("alerts", "webhook_deliveries"):
        rows = db.all(
            f"SELECT id, payload FROM {table} WHERE payload::text ~ %s ORDER BY created_at LIMIT %s",
            (_PLAIN_PRINCIPAL_KEY, limit),
        )
        sealed = failed = 0
        for row in rows:
            try:
                db.execute(
                    f"UPDATE {table} SET payload = %s WHERE id = %s",
                    (db.as_jsonb(pii.seal_principal_keys(row["payload"])), row["id"]),
                )
                sealed += 1
            except Exception as exc:  # noqa: BLE001 - one row must not stop the batch
                log.error("Could not seal %s payload %s: %s", table, row["id"], type(exc).__name__)
                failed += 1
        out[table] = sealed
        if failed:
            out[f"{table}_failed"] = failed
    return out


def prune_old_webhook_deliveries(days: int | None = None) -> dict[str, int]:
    """SEC-13 / P5-07: retention on webhook_deliveries.

    Terminal rows (dispatched, failed after the retry limit, or skipped with no
    configured webhook) are removed once they are older than `days`. SEC-13 made
    the queue stop holding plaintext OTP codes (rows are payload->>'otp
    encrypted), so a long retention no longer preserves secrets in the clear.
    P5-07: the delivery table is the channel of record for consent events and
    OTP dispatch, so the retention honours the Rule 6(1)(e) one-year floor
    (WEBHOOK_DELIVERY_RETENTION_DAYS) rather than a hard-coded 30 — and the
    floor is ENFORCED: the knob can never configure a retention shorter than the
    statute allows.
    """
    floor = RULE_6_1_E_MIN_RETENTION_DAYS
    requested = days or settings.webhook_delivery_retention_days
    effective = max(int(requested), floor)
    pruned = (
        db.execute(
            "DELETE FROM webhook_deliveries WHERE status IN ('DISPATCHED', 'FAILED', 'SKIPPED')"
            " AND created_at < NOW() - make_interval(days => %s)",
            (effective,),
        )
        or 0
    )
    return {"pruned": pruned, "retention_days": effective, "floor_enforced": effective == floor}


def prune_old_notification_deliveries(days: int | None = None) -> dict[str, int]:
    """SA-13: retention on notification_deliveries, which had none.

    Terminal delivery rows (SENT, FAILED, SKIPPED) carry the recipient address
    or device; they are removed once older than NOTIFICATION_DELIVERY_RETENTION_DAYS,
    never sooner than the Rule 6(1)(e) one-year floor (which db/23 also
    enforces in the database). The notifications row — the in-app record — is
    kept.
    """
    floor = RULE_6_1_E_MIN_RETENTION_DAYS
    requested = days or settings.notification_delivery_retention_days
    effective = max(int(requested), floor)
    pruned = (
        db.execute(
            "DELETE FROM notification_deliveries WHERE status IN ('SENT', 'FAILED', 'SKIPPED')"
            " AND created_at < NOW() - make_interval(days => %s)",
            (effective,),
        )
        or 0
    )
    return {"pruned": pruned, "retention_days": effective, "floor_enforced": effective == floor}
