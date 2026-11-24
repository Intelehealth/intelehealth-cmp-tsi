from __future__ import annotations

from dpdpcms_py.kernel import db, pii


def _dpo_recipient(fiduciary_id: str) -> str:
    row = db.one(
        "SELECT id FROM operators WHERE fiduciary_id = %s AND role = 'DPO' AND status = 'ACTIVE' ORDER BY created_at LIMIT 1",
        (fiduciary_id,),
    )
    return str(row["id"]) if row else fiduciary_id


def _notify(
    recipient_type: str, recipient_id: str, fiduciary_id: str, notification_type: str, context: dict | None = None
) -> None:
    """Queue a notification; the recipient id is stored as its _enc/_hmac pair (db/34)."""
    db.execute(
        "INSERT INTO notifications (recipient_type, recipient_id_enc, recipient_id_hmac, fiduciary_id,"
        f" notification_type, context) VALUES (%s, {pii.PID_VALUES}, %s, %s, %s)",
        (
            recipient_type,
            *pii.pid_params(recipient_id),
            fiduciary_id,
            notification_type,
            db.as_jsonb(context) if context is not None else None,
        ),
    )
