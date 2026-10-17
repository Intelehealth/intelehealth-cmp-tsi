from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta

import psycopg

from . import db, pii
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


# Every audit_logs column, in table order: the select list of each arm of the
# ledger_source() UNION, so an archive table (detached partition) and the live
# table line up column for column.
_LEDGER_COLUMNS = (
    "id, fiduciary_id, timestamp, user_id, service_type, service_id, audit_action, context_details,"
    " prev_log_hash, current_log_hash, digital_signature, system_metadata,"
    " purpose_id, consent_status, initiator, source_ip"
)
_ARCHIVE_TABLE = re.compile(r"audit_logs_y\d{4}_archive")
# Registered archives that still exist as tables, oldest year first.
_ARCHIVE_REGISTRY_SQL = (
    "SELECT r.partition_name FROM audit_log_archive_registry r"
    " JOIN pg_class c ON c.relname = r.partition_name AND c.relkind = 'r'"
    " JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'"
    " ORDER BY r.period_start"
)


def _archive_tables(rows) -> list[str]:
    """Registry names safe to interpolate into SQL; anything else is logged and skipped."""
    tables = []
    for row in rows:
        name = row.get("partition_name") if isinstance(row, dict) else None
        if isinstance(name, str) and _ARCHIVE_TABLE.fullmatch(name):
            tables.append(name)
        elif name is not None:
            log.error("Ignoring unexpected audit archive registry entry %r", name)
    return tables


def _newest_archived_row(cur) -> dict | None:
    """The newest row across the archive tables, for log_event when the live
    ledger is empty (every year archived), so the chain continues instead of
    restarting from genesis. Runs on log_event's own cursor, under its lock."""
    cur.execute("SELECT to_regclass('public.audit_log_archive_registry') IS NOT NULL AS present")
    present = cur.fetchone()
    if not present or not present.get("present"):
        return None
    cur.execute(_ARCHIVE_REGISTRY_SQL)
    tables = _archive_tables(cur.fetchall())
    if not tables:
        return None
    union = " UNION ALL ".join(f"SELECT current_log_hash, timestamp, id FROM {table}" for table in tables)
    cur.execute(f"SELECT current_log_hash, timestamp FROM ({union}) AS a ORDER BY timestamp DESC, id DESC LIMIT 1")
    return cur.fetchone()


def ledger_source() -> str:
    """The SQL FROM fragment that reads the WHOLE ledger: live + archived years.

    `audit_logs` alone when no year has been archived; otherwise a parenthesised
    UNION ALL of `audit_logs` and every archive table in
    audit_log_archive_registry, aliased `audit_logs`, so callers keep their
    column references. Registry names are interpolated into SQL, so only names
    of the exact archive shape are used; anything else is skipped and logged.
    """
    try:
        rows = db.all(_ARCHIVE_REGISTRY_SQL)
    except psycopg.Error:
        log.warning("audit_log_archive_registry unavailable; apply db/33_audit_archive_registry.sql", exc_info=True)
        return "audit_logs"
    tables = _archive_tables(rows)
    if not tables:
        return "audit_logs"
    arms = [f"SELECT {_LEDGER_COLUMNS} FROM {table}" for table in ["audit_logs", *tables]]
    return "(" + " UNION ALL ".join(arms) + ") AS audit_logs"


def _now() -> datetime:
    """The audit clock (a seam so tests can date a row in a chosen year)."""
    return datetime.now(UTC)


def row_hash(previous_hash: str | None, row: dict) -> str:
    """The v2 hash of one audit row, from its stored column values."""
    parts = [previous_hash or ""] + [_canonical_value(row.get(col), col) for col in _HASHED_COLUMNS]
    # JSON-encode the parts so a '|' inside a value cannot shift field boundaries.
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode("utf-8")).hexdigest()


# Detail keys whose value names a principal (Ruling K: the brief's set, all
# already in pii.PRINCIPAL_KEYS): log_event stores each as its
# principal_pseudonym, at any depth, so context_details carries no principal id
# (the row's own user_id column is pseudonymised the same way).
PRINCIPAL_DETAIL_KEYS = pii.PRINCIPAL_KEYS


def principal_pseudonym(value: str) -> str:
    """The audit pseudonym of a principal id: spaces trimmed (as pii.normalize), case kept."""
    return pseudonym(pii.normalize(value))


def _pseudonymise_details(value):
    """Copy of a details value with every principal key pseudonymised (None stays None)."""
    return pii.map_principal_keys(
        value, lambda key, item: (key, None if item is None else principal_pseudonym(pii.canonical_json(item)))
    )


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
    # A string details value is stored as given; a dict has its principal ids pseudonymised.
    context = details if isinstance(details, str) else json.dumps(_pseudonymise_details(details or {}), default=str)
    fid = fiduciary_id if fiduciary_id and fiduciary_id != ADMIN_FIDUCIARY_ID else None
    row = {
        "id": str(uuid.uuid4()),
        "fiduciary_id": fid,
        "user_id": principal_pseudonym(user_id) if user_id else "SYSTEM",
        "service_type": service_type,
        "service_id": service_id,
        "audit_action": action,
        "context_details": context,
        "purpose_id": purpose_id,
        "consent_status": consent_status,
        "initiator": initiator,
    }
    with db.connection() as conn, conn.cursor() as cur:
        # The client IP is stored encrypted; the row hash covers the ciphertext as stored.
        row["source_ip"] = None
        if source_ip:
            cur.execute(f"SELECT {db.enc_expr()} AS c", db.bind_encrypt(source_ip))
            row["source_ip"] = cur.fetchone()["c"]
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (AUDIT_CHAIN_LOCK,))
        # The predecessor is the newest LIVE row: archived years are always
        # older than every live one. Only when the live ledger is empty (every
        # year archived) is it the newest archived row.
        cur.execute("SELECT current_log_hash, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 1")
        previous = cur.fetchone() or _newest_archived_row(cur)
        previous_hash = previous["current_log_hash"] if previous else ""
        # audit_logs.timestamp is TIMESTAMP (no zone): store naive UTC so the value
        # hashed is the value stored, whatever the session TimeZone. Keep it
        # strictly increasing so timestamp order is chain order for the verifier.
        timestamp = _now().astimezone(UTC).replace(tzinfo=None)
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


def verify_chain(
    limit: int = 100_000,
    fiduciary_id: str | None = None,
    since: datetime | str | None = None,
    until: datetime | str | None = None,
) -> dict:
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

    P10-06: `until` closes the window (exclusive), so a verdict for a historical
    export examines the rows that export holds - not the newest `limit` rows of
    the ledger - and the newest row of the window must be the one its successor
    links to, or a row deleted just above the window would go unnoticed.
    """
    cols = ", ".join(_HASHED_COLUMNS)
    # Archived years included, so a window reaching back past the live
    # partitions still verifies (and its links across the boundary are checked).
    source = ledger_source()
    select = f"SELECT {cols}, prev_log_hash, current_log_hash, system_metadata FROM {source} "
    bounds, bound_params = [], []
    if since is not None:
        bounds.append("timestamp >= %s::timestamp")
        bound_params.append(_naive_utc(since))
    if until is not None:
        bounds.append("timestamp < %s::timestamp")
        bound_params.append(_naive_utc(until))
    window = f"WHERE {' AND '.join(bounds)} " if bounds else ""
    fetched = db.all(
        select + window + "ORDER BY timestamp DESC, id DESC LIMIT %s",
        (*bound_params, limit + 1),
    )
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
            f"SELECT current_log_hash FROM {source} WHERE (timestamp, id) < (%s, %s)"
            " ORDER BY timestamp DESC, id DESC LIMIT 1",
            (oldest["timestamp"], oldest["id"]),
        )
        if predecessor and (oldest.get("prev_log_hash") or "") != (predecessor.get("current_log_hash") or ""):
            flag(oldest, "LINK_MISMATCH")
    if until is not None and rows:
        newest = rows[0]
        successor = db.one(
            f"SELECT id, fiduciary_id, prev_log_hash FROM {source} WHERE (timestamp, id) > (%s, %s)"
            " ORDER BY timestamp ASC, id ASC LIMIT 1",
            (newest["timestamp"], newest["id"]),
        )
        if successor and (successor.get("prev_log_hash") or "") != (newest.get("current_log_hash") or ""):
            flag(successor, "LINK_MISMATCH")

    # An untruncated window holds every row in scope by construction; only a
    # truncated one needs the scope's real row count to say what was missed.
    scope_total = _count_rows(fiduciary_id, since, until, source) if truncated else in_scope_total
    # Zero in-scope rows is never a clean bill of health (P7-02).
    unexamined_tenant = fiduciary_id is not None and in_scope_total == 0
    if since is not None or until is not None:
        coverage_complete = not truncated
    else:
        coverage_complete = in_scope_total >= scope_total
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
        "anchored_until": _naive_utc(until).isoformat() if until is not None else None,
    }


def _naive_utc(value: datetime | str) -> datetime:
    """audit_logs.timestamp is TIMESTAMP (no zone) holding naive UTC."""
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)
    return value


def _count_rows(
    fiduciary_id: str | None,
    since: datetime | str | None,
    until: datetime | str | None = None,
    source: str = "audit_logs",
) -> int:
    where, params = [], []
    if fiduciary_id is not None:
        where.append("fiduciary_id = %s")
        params.append(fiduciary_id)
    if since is not None:
        where.append("timestamp >= %s::timestamp")
        params.append(_naive_utc(since))
    if until is not None:
        where.append("timestamp < %s::timestamp")
        params.append(_naive_utc(until))
    clause = f" WHERE {' AND '.join(where)}" if where else ""
    row = db.one(f"SELECT count(*) AS n FROM {source}{clause}", params)
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


AUDIT_READ_MAX = 5000


# The readable client IP of an audit row for the console reads (db/35
# tsi_audit_source_ip: decrypted, or a pre-db/35 plaintext IP as stored); bind
# *db.bind_key(). Exports keep the stored ciphertext so the chain re-verifies.
SOURCE_IP_SQL = "tsi_audit_source_ip(source_ip, %s)"


def list_logs(payload: dict) -> list[dict]:
    from .services.base import canonical_purpose_id

    params: list = [*db.bind_key()]
    where = ["1=1"]
    if payload.get("fiduciary_id"):
        where.append("fiduciary_id = %s")
        params.append(payload["fiduciary_id"])
    if payload.get("user_id"):
        where.append("user_id = %s")
        params.append(principal_pseudonym(payload["user_id"]))
    if payload.get("audit_action"):
        where.append("audit_action = %s")
        params.append(payload["audit_action"])
    if payload.get("purpose_id"):
        # P11-04: the same canonical form the services write, so the 'ALL'
        # whole-account erasure sentinel is found as 'ALL'; tsi_canonical_purpose
        # (db/26) folds legacy rows written before canonicalisation.
        where.append("tsi_canonical_purpose(purpose_id) = %s")
        params.append(canonical_purpose_id(payload["purpose_id"]))
    if payload.get("initiator"):
        where.append("initiator = %s")
        params.append(payload["initiator"])
    # R6-c: one read returns at most AUDIT_READ_MAX rows; bulk export is the
    # AUDIT job, which writes a re-verifiable file instead.
    limit = min(max(int(payload.get("limit") or 50), 1), AUDIT_READ_MAX)
    params.append(limit)
    return db.to_jsonable(
        db.all(
            f"""
        SELECT id, fiduciary_id, timestamp, user_id, service_type, service_id,
               audit_action, context_details, prev_log_hash, current_log_hash,
               purpose_id, consent_status, initiator, {SOURCE_IP_SQL} AS source_ip, system_metadata
        FROM {ledger_source()}
        WHERE {" AND ".join(where)}
        ORDER BY timestamp DESC
        LIMIT %s
        """,
            params,
        )
    )


def get_log(log_id: str) -> dict | None:
    row = db.one(
        f"SELECT *, {SOURCE_IP_SQL} AS source_ip_plain FROM {ledger_source()} WHERE id = %s", (*db.bind_key(), log_id)
    )
    if row:
        row["source_ip"] = row.pop("source_ip_plain")
    return db.to_jsonable(row)
