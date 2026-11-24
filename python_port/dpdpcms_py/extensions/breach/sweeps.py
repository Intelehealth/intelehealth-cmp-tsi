from __future__ import annotations

from dpdpcms_py.kernel import db
from dpdpcms_py.modules.notifications.api import _dpo_recipient, _notify

# s.8(6) / Rule 7(2): the 72-hour Board intimation clock. A breach whose
# intimation is not recorded raises a DUE alert inside the last 12 hours and a
# MISSED alert once the deadline passes - each once per breach.
BREACH_DUE_WARNING_HOURS = 12


def flag_breach_board_deadlines() -> dict[str, int]:
    """S8-6: nothing watched board_notification_deadline."""
    from dpdpcms_py.modules.notifications.api import record_alert

    rows = db.all(
        """
        SELECT b.id, b.fiduciary_id, b.title, b.board_notification_deadline,
               CASE WHEN b.board_notification_deadline <= NOW() THEN 'BREACH_BOARD_DEADLINE_MISSED'
                    ELSE 'BREACH_BOARD_DEADLINE_DUE' END AS alert_type
        FROM breach_incidents b
        WHERE b.board_notified_at IS NULL AND b.board_notification_deadline IS NOT NULL
          AND b.board_notification_deadline <= NOW() + make_interval(hours => %s)
          AND NOT EXISTS (
                SELECT 1 FROM alerts a
                WHERE a.fiduciary_id = b.fiduciary_id AND a.event_ref_id = b.id::text
                  AND a.alert_type = CASE WHEN b.board_notification_deadline <= NOW()
                                          THEN 'BREACH_BOARD_DEADLINE_MISSED' ELSE 'BREACH_BOARD_DEADLINE_DUE' END
          )
        """,
        (BREACH_DUE_WARNING_HOURS,),
    )
    for row in rows:
        fid = str(row["fiduciary_id"])
        record_alert(
            fid,
            row["alert_type"],
            str(row["id"]),
            {"breach_id": str(row["id"]), "deadline": row["board_notification_deadline"].isoformat()},
        )
        _notify(
            "DPO",
            _dpo_recipient(fid),
            fid,
            row["alert_type"],
            {"title": row["title"], "deadline": row["board_notification_deadline"].isoformat()},
        )
    return {"alerted": len(rows)}
