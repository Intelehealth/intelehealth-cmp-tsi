from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta

import psycopg

from . import db
from .context import ADMIN_FIDUCIARY_ID
from .security import pseudonym

log = logging.getLogger("dpdpcms.audit")

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
    return hmac.new(settings.certificate_signing_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def verify_chain(limit: int = 100_000, fiduciary_id: str | None = None, since: datetime | str | None = None) -> dict:
    """LG-04: walk the ledger and recompute it.

    The walk is NEWEST-first and stops at `limit` rows, so the most recent
    activity — where tampering would actually be attempted and noticed — is
    always inside the checked window (SEC-10). Everything a v2 row links to and
    every v2 row's own hash are verified; rows from before v2 are checked for
    linkage only and counted as legacy.

    P6-01: the linkage check ALWAYS runs against the unfiltered chain, because
    the chain is global — `log_event` picks its predecessor with no fiduciary
    filter, and ADMIN events are normalised to a NULL fiduciary. `fiduciary_id`
    only narrows the REPORT, so a tenant-scoped DPO verifies its own ledger and
    learns no other tenant's row ids.

    SEC-10: a break in ANOTHER tenant's rows still breaks the chain a scoped
    tenant's evidence rests on, so it makes `intact` false; it is reported as a
    count (`foreign_broken_count`) without ids.

    P7-02 / P8-04: `since` anchors the window on a timestamp (a certificate's
    oldest trail entry) instead of a row count, so every row from the anchor to
    the head — and the anchor row's link to its predecessor — is examined.
    `coverage_complete` says whether every in-scope row the question covers was
    examined: with `since`, that the window was not truncated; without it, that
    rows_checked equals the scope's real row count. Callers that certify refuse
    on an incomplete window rather than on the old (unreachable) truncation test.
    """
    cols = ", ".join(_HASHED_COLUMNS)
    select = f"SELECT {cols}, prev_log_hash, current_log_hash, system_metadata FROM audit_logs "
    if since is not None:
        fetched = db.all(
            select + "WHERE timestamp >= %s::timestamp ORDER BY timestamp DESC, id DESC LIMIT %s",
            (_naive_utc(since), limit + 1),
        )
    else:
        fetched = db.all(select + "ORDER BY timestamp DESC, id DESC LIMIT %s", (limit + 1,))
    truncated = len(fetched) > limit
    rows = fetched[:limit]
    broken: list[dict] = []
    foreign_broken = 0
    legacy = 0
    tenant_checked = 0
    in_scope_total = 0

    def scoped(row: dict) -> bool:
        return fiduciary_id is None or str(row.get("fiduciary_id") or "") == str(fiduciary_id)

    def flag(row: dict, reason: str) -> None:
        nonlocal foreign_broken
        if scoped(row):
            broken.append({"id": str(row["id"]), "reason": reason})
        else:
            foreign_broken += 1

    for index, row in enumerate(rows):
        meta = row.get("system_metadata") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except ValueError:
                meta = {}
        in_scope = scoped(row)
        if in_scope:
            in_scope_total += 1
        # `row` is older than `rows[index - 1]` (we walk newest first): the
        # newer row's prev_log_hash must equal this row's current_log_hash.
        if index > 0 and (rows[index - 1].get("prev_log_hash") or "") != (row.get("current_log_hash") or ""):
            flag(rows[index - 1], "LINK_MISMATCH")
        if meta.get("hash_v") == HASH_VERSION:
            if row_hash(row.get("prev_log_hash"), row) != row.get("current_log_hash"):
                flag(row, "CONTENT_MISMATCH")
            if in_scope:
                tenant_checked += 1
        elif in_scope:
            legacy += 1
    # The oldest row of an anchored window must still link to its predecessor,
    # or a row deleted just below the anchor would go unnoticed.
    if since is not None and rows and not truncated:
        oldest = rows[-1]
        predecessor = db.one(
            "SELECT current_log_hash FROM audit_logs WHERE (timestamp, id) < (%s, %s)"
            " ORDER BY timestamp DESC, id DESC LIMIT 1",
            (oldest["timestamp"], oldest["id"]),
        )
        if predecessor and (oldest.get("prev_log_hash") or "") != (predecessor.get("current_log_hash") or ""):
            flag(oldest, "LINK_MISMATCH")

    # An untruncated window holds every row in scope by construction; only a
    # truncated one needs the scope's real row count to say what was missed.
    scope_total = _count_rows(fiduciary_id, since) if truncated else in_scope_total
    # Zero in-scope rows is never a clean bill of health (P7-02).
    unexamined_tenant = fiduciary_id is not None and in_scope_total == 0
    coverage_complete = not truncated if since is not None else in_scope_total >= scope_total
    return {
        "intact": not broken and not foreign_broken and not unexamined_tenant,
        # P6-13: rows_checked means the same thing at every scope — the in-scope
        # rows examined — and the breakdown is reported separately.
        "rows_checked": in_scope_total,
        "rows_verified": tenant_checked,
        "rows_in_scope_total": scope_total,
        "rows_unexamined": max(scope_total - in_scope_total, 0),
        "legacy_rows_linkage_only": legacy,
        "broken": broken[:100],
        "broken_count": len(broken),
        "foreign_broken_count": foreign_broken,
        "truncated": truncated,
        "coverage_complete": coverage_complete,
        "unexamined_tenant": unexamined_tenant,
        "anchored_since": _naive_utc(since).isoformat() if since is not None else None,
    }


def _naive_utc(value: datetime | str) -> datetime:
    """audit_logs.timestamp is TIMESTAMP (no zone) holding naive UTC."""
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)
    return value


def _count_rows(fiduciary_id: str | None, since: datetime | str | None) -> int:
    where, params = [], []
    if fiduciary_id is not None:
        where.append("fiduciary_id = %s")
        params.append(fiduciary_id)
    if since is not None:
        where.append("timestamp >= %s::timestamp")
        params.append(_naive_utc(since))
    clause = f" WHERE {' AND '.join(where)}" if where else ""
    row = db.one(f"SELECT count(*) AS n FROM audit_logs{clause}", params)
    return int((row or {}).get("n") or 0)


def record_chain_verification(limit: int = 5_000_000) -> dict:
    """P6-12: the full-ledger walk runs in the worker, not the request thread.

    Claims at most one run per day (job_schedule_state), walks the whole
    unfiltered chain and stores the verdict, so a DPO reads the latest
    platform-wide result without hashing every tenant's rows on request.
    """
    claimed = db.one(
        """
        INSERT INTO job_schedule_state (job_name, last_run_date) VALUES ('audit_chain_verification', CURRENT_DATE)
        ON CONFLICT (job_name) DO UPDATE SET last_run_date = EXCLUDED.last_run_date
            WHERE job_schedule_state.last_run_date < EXCLUDED.last_run_date
        RETURNING job_name
        """
    )
    if not claimed:
        return {"skipped": True}
    try:
        result = verify_chain(limit)
        _store_chain_verdict(result)
    except Exception:
        # Release today's claim so the next worker cycle retries the walk.
        db.execute(
            "UPDATE job_schedule_state SET last_run_date = CURRENT_DATE - 1 WHERE job_name = 'audit_chain_verification'"
        )
        raise
    return {"intact": result["intact"], "rows_checked": result["rows_checked"], "broken_count": result["broken_count"]}


def _store_chain_verdict(result: dict) -> None:
    db.execute(
        """
        INSERT INTO audit_chain_verifications (intact, rows_checked, broken_count, truncated, coverage_complete, result)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            result["intact"],
            result["rows_checked"],
            result["broken_count"],
            result["truncated"],
            result["coverage_complete"],
            db.as_jsonb({key: value for key, value in result.items() if key != "broken"}),
        ),
    )


def latest_chain_verification() -> dict | None:
    """P6-12: the most recent background full-ledger verdict, if any."""
    try:
        row = db.one(
            "SELECT verified_at, intact, rows_checked, broken_count, truncated, coverage_complete"
            " FROM audit_chain_verifications ORDER BY verified_at DESC LIMIT 1"
        )
    except psycopg.Error:
        # db/24 not applied yet: report no background verdict rather than fail
        # the on-demand verification it accompanies.
        log.warning("audit_chain_verifications unavailable; apply db/24_p8_remediation.sql", exc_info=True)
        return None
    return db.to_jsonable(row) if row else None


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
