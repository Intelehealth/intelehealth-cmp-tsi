from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from . import db
from .context import ADMIN_FIDUCIARY_ID
from .security import pseudonym


def log_event(
    user_id: str | None,
    fiduciary_id: str | None,
    service_type: str,
    service_id: str | None,
    action: str,
    details: str | dict | None = None,
) -> None:
    context = details if isinstance(details, str) else json.dumps(details or {}, default=str)
    fid = fiduciary_id if fiduciary_id and fiduciary_id != ADMIN_FIDUCIARY_ID else None
    previous = db.one("SELECT current_log_hash FROM audit_logs ORDER BY timestamp DESC LIMIT 1")
    previous_hash = previous["current_log_hash"] if previous else ""
    timestamp = datetime.now(timezone.utc)
    canonical = "|".join([previous_hash or "", timestamp.isoformat(), user_id or "", service_type, action, context])
    current_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    db.execute(
        """
        INSERT INTO audit_logs
            (id, fiduciary_id, timestamp, user_id, service_type, service_id,
             audit_action, context_details, prev_log_hash, current_log_hash, system_metadata)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            str(uuid.uuid4()),
            fid,
            timestamp,
            pseudonym(user_id) if user_id else "SYSTEM",
            service_type,
            service_id,
            action,
            context,
            previous_hash,
            current_hash,
            db.as_jsonb({"python_port": True}),
        ),
    )


def list_logs(payload: dict) -> list[dict]:
    params: list = []
    where = ["1=1"]
    if payload.get("fiduciary_id"):
        where.append("fiduciary_id = %s")
        params.append(payload["fiduciary_id"])
    if payload.get("user_id"):
        where.append("user_id = %s")
        params.append(pseudonym(payload["user_id"]))
    if payload.get("audit_action"):
        where.append("audit_action = %s")
        params.append(payload["audit_action"])
    limit = int(payload.get("limit") or 50)
    params.append(limit)
    return db.to_jsonable(db.all(
        f"""
        SELECT id, fiduciary_id, timestamp, user_id, service_type, service_id,
               audit_action, context_details, prev_log_hash, current_log_hash
        FROM audit_logs
        WHERE {' AND '.join(where)}
        ORDER BY timestamp DESC
        LIMIT %s
        """,
        params,
    ))


def get_log(log_id: str) -> dict | None:
    return db.to_jsonable(db.one("SELECT * FROM audit_logs WHERE id = %s", (log_id,)))
