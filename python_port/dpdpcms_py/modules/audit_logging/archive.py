from __future__ import annotations

import logging
import re
from datetime import UTC, datetime

from dpdpcms_py.kernel import db
from dpdpcms_py.kernel.config import settings
from psycopg import sql

log = logging.getLogger("dpdpcms.jobs")


# ---- yearly audit partitions (db/32, db/33) --------------------------------------
# Serialises partition DDL between concurrent workers (arbitrary bigint key).
AUDIT_PARTITION_LOCK = 724521054


_AUDIT_YEAR_PARTITION = re.compile(r"audit_logs_y(\d{4})")


_APPEND_ONLY_TRIGGERS = (
    ("trg_audit_logs_no_update_delete", "BEFORE UPDATE OR DELETE", "FOR EACH ROW"),
    ("trg_audit_logs_no_truncate", "BEFORE TRUNCATE", "FOR EACH STATEMENT"),
)


def _year_bounds(year: int) -> tuple[datetime, datetime]:
    return datetime(year, 1, 1), datetime(year + 1, 1, 1)


def _add_append_only_triggers(cur, table: str, triggers=_APPEND_ONLY_TRIGGERS) -> None:
    for name, timing, level in triggers:
        cur.execute(sql.SQL("DROP TRIGGER IF EXISTS {} ON {}").format(sql.Identifier(name), sql.Identifier(table)))
        cur.execute(
            sql.SQL(
                "CREATE TRIGGER {} " + timing + " ON {} " + level + " EXECUTE FUNCTION audit_logs_append_only()"
            ).format(sql.Identifier(name), sql.Identifier(table))
        )


def _copy_audit_access_controls(cur, table: str) -> None:
    """Give an archive table the same row-level security (ENABLE/FORCE and
    every policy) and the same grants as audit_logs, so reads through
    audit.ledger_source() work for every role that can read audit_logs and
    stay tenant-scoped (db/28, db/30)."""
    ident = sql.Identifier(table)
    cur.execute(
        "SELECT relrowsecurity, relforcerowsecurity, pg_get_userbyid(relowner) AS owner"
        " FROM pg_class WHERE oid = 'public.audit_logs'::regclass"
    )
    parent = cur.fetchone()
    if parent["relrowsecurity"]:
        cur.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(ident))
    if parent["relforcerowsecurity"]:
        cur.execute(sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY").format(ident))
    cur.execute(
        "SELECT policyname, permissive, roles::text[] AS roles, cmd, qual, with_check FROM pg_policies"
        " WHERE schemaname = 'public' AND tablename = 'audit_logs'"
    )
    for policy in cur.fetchall():
        roles = sql.SQL(", ").join(
            sql.SQL("PUBLIC") if role == "public" else sql.Identifier(role) for role in policy["roles"]
        )
        # qual / with_check are deparsed expressions from the catalog itself.
        statement = sql.SQL("CREATE POLICY {} ON {} AS {} FOR {} TO {}").format(
            sql.Identifier(policy["policyname"]),
            ident,
            sql.SQL(policy["permissive"]),
            sql.SQL(policy["cmd"]),
            roles,
        )
        if policy["qual"] is not None:
            statement += sql.SQL(" USING (" + policy["qual"] + ")")
        if policy["with_check"] is not None:
            statement += sql.SQL(" WITH CHECK (" + policy["with_check"] + ")")
        cur.execute(sql.SQL("DROP POLICY IF EXISTS {} ON {}").format(sql.Identifier(policy["policyname"]), ident))
        cur.execute(statement)
    cur.execute(
        "SELECT grantee, privilege_type FROM information_schema.role_table_grants"
        " WHERE table_schema = 'public' AND table_name = 'audit_logs' AND grantee <> %s",
        (parent["owner"],),
    )
    for grant in cur.fetchall():
        grantee = sql.SQL("PUBLIC") if grant["grantee"] == "PUBLIC" else sql.Identifier(grant["grantee"])
        cur.execute(sql.SQL("GRANT " + grant["privilege_type"] + " ON {} TO {}").format(ident, grantee))


def _attached_audit_years(cur) -> dict[int, str]:
    cur.execute(
        "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid"
        " WHERE i.inhparent = 'public.audit_logs'::regclass"
    )
    years = {}
    for row in cur.fetchall():
        match = _AUDIT_YEAR_PARTITION.fullmatch(row["relname"])
        if match:
            years[int(match.group(1))] = row["relname"]
    return years


def _ensure_audit_year_partition(year: int) -> bool:
    """Create audit_logs_y<year> if missing. True when it was created."""
    name = f"audit_logs_y{year}"
    start, end = _year_bounds(year)
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (AUDIT_PARTITION_LOCK,))
        if year in _attached_audit_years(cur):
            return False
        cur.execute("SELECT to_regclass(%s) AS r", (f"public.{name}",))
        if cur.fetchone()["r"] is not None:
            log.error("Table %s exists but is not an audit_logs partition; not creating it", name)
            return False
        # A row already caught by DEFAULT for this year would make the new
        # partition's bound overlap it; leave the year in DEFAULT.
        cur.execute(
            "SELECT 1 FROM audit_logs_default WHERE timestamp >= %s AND timestamp < %s LIMIT 1",
            (start, end),
        )
        if cur.fetchone():
            log.warning("audit_logs_default holds %s rows; partition %s not created", year, name)
            return False
        cur.execute(
            sql.SQL("CREATE TABLE {} PARTITION OF audit_logs FOR VALUES FROM ({}) TO ({})").format(
                sql.Identifier(name), sql.Literal(start), sql.Literal(end)
            )
        )
        # Row triggers are cloned from the parent; TRUNCATE ones are not.
        _add_append_only_triggers(cur, name, _APPEND_ONLY_TRIGGERS[1:])
    log.info("Created audit_logs partition %s", name)
    return True


def _archive_audit_year(year: int) -> bool:
    """Detach audit_logs_y<year>, rename it audit_logs_y<year>_archive, keep it
    append-only and register it. Never deletes a row. True when archived."""
    name = f"audit_logs_y{year}"
    archive = f"{name}_archive"
    start, end = _year_bounds(year)
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (AUDIT_PARTITION_LOCK,))
        if year not in _attached_audit_years(cur):
            return False
        cur.execute("SELECT to_regclass(%s) AS r", (f"public.{archive}",))
        if cur.fetchone()["r"] is not None:
            log.error("Archive table %s already exists; %s left attached", archive, name)
            return False
        cur.execute(sql.SQL("ALTER TABLE audit_logs DETACH PARTITION {}").format(sql.Identifier(name)))
        cur.execute(sql.SQL("ALTER TABLE {} RENAME TO {}").format(sql.Identifier(name), sql.Identifier(archive)))
        # DETACH drops the row triggers cloned from the parent.
        _add_append_only_triggers(cur, archive)
        _copy_audit_access_controls(cur, archive)
        cur.execute(sql.SQL("SELECT count(*) AS n FROM {}").format(sql.Identifier(archive)))
        row_count = int(cur.fetchone()["n"])
        cur.execute(
            "INSERT INTO audit_log_archive_registry (partition_name, period_start, period_end, row_count)"
            " VALUES (%s, %s, %s, %s)",
            (archive, start, end, row_count),
        )
    log.info("Archived audit_logs partition %s as %s (%s rows)", name, archive, row_count)
    return True


def archive_audit_partitions(now: datetime | None = None) -> dict[str, int]:
    """Keep audit_logs partitioned ahead of time and archive old years.

    Ensures this year's and next year's partitions exist (so a Dec 31 -> Jan 1
    rollover never lands in DEFAULT), then detaches every yearly partition
    older than the AUDIT_LIVE_YEARS window (current year included) into a
    standalone, still append-only archive table recorded in
    audit_log_archive_registry. Archives stay readable through
    audit.ledger_source(); nothing is deleted. Each partition is handled in
    its own transaction.
    """
    now = now or datetime.now(UTC)
    if now.tzinfo is not None:
        now = now.astimezone(UTC)
    created = sum(_ensure_audit_year_partition(year) for year in (now.year, now.year + 1))
    oldest_live = now.year - (max(int(settings.audit_live_years), 1) - 1)
    with db.connection() as conn, conn.cursor() as cur:
        years = sorted(_attached_audit_years(cur))
    archived = sum(_archive_audit_year(year) for year in years if year < oldest_live)
    return {"created": created, "archived": archived}
