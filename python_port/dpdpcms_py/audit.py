from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from . import db
from .context import ADMIN_FIDUCIARY_ID
from .security import pseudonym

# Serialises the read-last-hash / insert pair so concurrent writers chain from the
# same predecessor rather than forking the chain. Held for the length of the
# transaction (xact lock) and released on commit.
AUDIT_CHAIN_LOCK = 724521053  # arbitrary constant bigint advisory lock key

# LG-04: version 2 hashes every stored column, exactly as stored, so the chain can
# be recomputed from the table alone. Version-1 rows (python_port rows written
# before this change) hashed the raw user_id and only a few columns; for those
# only the prev/current linkage can be checked.
HASH_VERSION = 2
_HASHED_COLUMNS = (
    "id",
    "fiduciary_id",
    "timestamp",
    "user_id",
    "service_type",
    "service_id",
    "audit_action",
    "context_details",
    "purpose_id",
    "consent_status",
    "initiator",
    "source_ip",
)


_UUID_COLUMNS = {"id", "fiduciary_id", "service_id"}


def _canonical_value(value, column: str = "") -> str:
    if value is None:
        return ""
    if column in _UUID_COLUMNS:
        # UUID columns read back lower-case and hyphenated whatever was written.
        try:
            return str(uuid.UUID(str(value)))
        except ValueError:
            return str(value)
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(UTC).replace(tzinfo=None)
        return value.isoformat(timespec="microseconds")
    return str(value)


def row_hash(previous_hash: str | None, row: dict) -> str:
    """The v2 hash of one audit row, from its stored column values."""
    parts = [previous_hash or ""] + [_canonical_value(row.get(col), col) for col in _HASHED_COLUMNS]
    # JSON-encode the parts so a '|' inside a value cannot shift field boundaries.
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode("utf-8")).hexdigest()


def log_event(
    user_id: str | None,
    fiduciary_id: str | None,
    service_type: str,
    service_id: str | None,
    action: str,
    details: str | dict | None = None,
    *,
    purpose_id: str | None = None,
    consent_status: str | None = None,
    initiator: str | None = None,
    source_ip: str | None = None,
) -> None:
    context = details if isinstance(details, str) else json.dumps(details or {}, default=str)
    fid = fiduciary_id if fiduciary_id and fiduciary_id != ADMIN_FIDUCIARY_ID else None
    row = {
        "id": str(uuid.uuid4()),
        "fiduciary_id": fid,
        "user_id": pseudonym(user_id) if user_id else "SYSTEM",
        "service_type": service_type,
        "service_id": service_id,
        "audit_action": action,
        "context_details": context,
        "purpose_id": purpose_id,
        "consent_status": consent_status,
        "initiator": initiator,
        "source_ip": source_ip,
    }
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (AUDIT_CHAIN_LOCK,))
        cur.execute("SELECT current_log_hash, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 1")
        previous = cur.fetchone()
        previous_hash = previous["current_log_hash"] if previous else ""
        # audit_logs.timestamp is TIMESTAMP (no zone): store naive UTC so the value
        # hashed is the value stored, whatever the session TimeZone. Keep it
        # strictly increasing so timestamp order is chain order for the verifier.
        timestamp = datetime.now(UTC).replace(tzinfo=None)
        last = previous.get("timestamp") if previous else None
        if last is not None and last.tzinfo is not None:
            last = last.astimezone(UTC).replace(tzinfo=None)
        if last is not None and timestamp <= last:
            timestamp = last + timedelta(microseconds=1)
        row["timestamp"] = timestamp
        current_hash = row_hash(previous_hash, row)
        cur.execute(
            """
            INSERT INTO audit_logs
                (id, fiduciary_id, timestamp, user_id, service_type, service_id,
                 audit_action, context_details, prev_log_hash, current_log_hash,
                 system_metadata, purpose_id, consent_status, initiator, source_ip)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                row["id"],
                row["fiduciary_id"],
                row["timestamp"],
                row["user_id"],
                row["service_type"],
                row["service_id"],
                row["audit_action"],
                row["context_details"],
                previous_hash,
                current_hash,
                db.as_jsonb({"python_port": True, "hash_v": HASH_VERSION}),
                row["purpose_id"],
                row["consent_status"],
                row["initiator"],
                row["source_ip"],
            ),
        )


def certificate_signature(data: dict) -> str:
    """HMAC-SHA256 over the canonical JSON of an evidence certificate (SEC-10).

    Canonicalisation is `json.dumps(sort_keys=True, ensure_ascii=False)` over
    every field except ``signature``, which is computed afterwards so the digest
    never covers itself. Generation and verification both call this function so
    the rule lives in exactly one place and a future verifier does not have to
    rediscover it.
    """
    from .config import settings

    payload = {key: value for key, value in data.items() if key != "signature"}
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hmac.new(
        settings.certificate_signing_key.encode("utf-8"), canonical, hashlib.sha256
    ).hexdigest()


def verify_chain(limit: int = 100_000, fiduciary_id: str | None = None) -> dict:
    """LG-04: walk the ledger and recompute it.

    The walk is NEWEST-first and stops at `limit` rows, so the most recent
    activity — where tampering would actually be attempted and noticed — is
    always inside the checked window (SEC-10). Everything a v2 row links to and
    every v2 row's own hash are verified; rows from before v2 are checked for
    linkage only and counted as legacy.

    When `fiduciary_id` is given, only that tenant's rows are checked, so a
    tenant-scoped DPO can verify its own ledger without learning other tenants'
    row ids.
    """
    cols = ", ".join(_HASHED_COLUMNS)
    where = "WHERE fiduciary_id = %s" if fiduciary_id else ""
    params: list[Any] = [fiduciary_id] if fiduciary_id else []
    rows = db.all(
        f"SELECT {cols}, prev_log_hash, current_log_hash, system_metadata FROM audit_logs {where} "
        "ORDER BY timestamp DESC, id DESC LIMIT %s",
        (*params, limit),
    )
    broken: list[dict] = []
    legacy = 0
    for index, row in enumerate(rows):
        meta = row.get("system_metadata") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except ValueError:
                meta = {}
        # `row` is older than `rows[index - 1]` (we walk newest first): the
        # newer row's prev_log_hash must equal this row's current_log_hash.
        if index > 0 and (rows[index - 1].get("prev_log_hash") or "") != (row.get("current_log_hash") or ""):
            broken.append({"id": str(rows[index - 1]["id"]), "reason": "LINK_MISMATCH"})
        if meta.get("hash_v") == HASH_VERSION:
            if row_hash(row.get("prev_log_hash"), row) != row.get("current_log_hash"):
                broken.append({"id": str(row["id"]), "reason": "CONTENT_MISMATCH"})
        else:
            legacy += 1
    return {
        "intact": not broken,
        "rows_checked": len(rows),
        "legacy_rows_linkage_only": legacy,
        "broken": broken[:100],
        "broken_count": len(broken),
        "truncated": len(rows) == limit,
    }


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
    if payload.get("purpose_id"):
        where.append("purpose_id = %s")
        params.append(payload["purpose_id"])
    if payload.get("initiator"):
        where.append("initiator = %s")
        params.append(payload["initiator"])
    limit = int(payload.get("limit") or 50)
    params.append(limit)
    return db.to_jsonable(
        db.all(
            f"""
        SELECT id, fiduciary_id, timestamp, user_id, service_type, service_id,
               audit_action, context_details, prev_log_hash, current_log_hash,
               purpose_id, consent_status, initiator, source_ip
        FROM audit_logs
        WHERE {" AND ".join(where)}
        ORDER BY timestamp DESC
        LIMIT %s
        """,
            params,
        )
    )


def get_log(log_id: str) -> dict | None:
    return db.to_jsonable(db.one("SELECT * FROM audit_logs WHERE id = %s", (log_id,)))
