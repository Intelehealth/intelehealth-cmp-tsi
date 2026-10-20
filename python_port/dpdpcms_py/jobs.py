from __future__ import annotations

import csv
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from psycopg import sql

from . import db, pii
from .audit import log_event
from .config import settings
from .services.base import csv_safe
from .services.lifecycle import close_purpose_exec

log = logging.getLogger("dpdpcms.jobs")


def _claim_pending_purges(fiduciary_id: str, purpose_id: str, trigger: str) -> bool:
    # purge_requests.purpose_id is canonical (db/26), as is every lifecycle id
    # this is called with, so an exact match is the canonical match (P10-09).
    """True when no non-terminal purge request already covers (fid, purpose, trigger)."""
    row = db.one(
        """
        SELECT 1 FROM purge_requests
        WHERE fiduciary_id = %s AND purpose_id = %s AND trigger_event = %s
          AND status IN ('PENDING', 'IN_PROGRESS')
        LIMIT 1
        """,
        (fiduciary_id, purpose_id, trigger),
    )
    return row is None


def close_due_time_bound_purposes() -> dict[str, int]:
    """PL-01: a TIME_BOUND purpose whose consent window has elapsed is closed.

    Closing reuses the full closure pipeline (purge requests, principal
    notifications, fiduciary alert, webhook, audit) — the same path as the DPO
    closing a purpose by hand through close_purpose.
    """
    due = db.all(
        """
        SELECT fiduciary_id, purpose_id, opened_at, consent_expiry_days
        FROM purpose_lifecycle
        WHERE duration_type = 'TIME_BOUND' AND state = 'OPEN' AND consent_expiry_days IS NOT NULL
          AND opened_at + make_interval(days => consent_expiry_days) <= NOW()
        ORDER BY opened_at
        LIMIT %s
        """,
        (settings.worker_batch_size,),
    )
    closed = 0
    errors = 0
    for row in due:
        fid = str(row["fiduciary_id"])
        purpose_id = str(row["purpose_id"])
        try:
            close_purpose_exec(
                fiduciary_id=fid,
                purpose_id=purpose_id,
                reason="Time-bound purpose reached its consent_expiry_days under the purpose lifecycle (PL-01).",
                deidentification_action="ERASE",
                closed_by=None,
            )
            closed += 1
        except Exception:
            # P11-08: a failed closure is an error the operator sees in the
            # cycle summary, never an innocent-looking "closed: 0".
            errors += 1
            log.exception("Time-bound closure failed for %s/%s", fid, purpose_id)
    out = {"closed": closed, "scanned": len(due)}
    if errors:
        out["errors"] = errors
        out["error"] = f"{errors} time-bound closure(s) failed; see the worker log."
    return out


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


def escalate_overdue_grievances() -> dict[str, int]:
    """UD-12 / GR-09: auto-escalate grievances past their SLA due date."""
    # GR-09: escalate once the SLA due date plus the configured grace period
    # (GRIEVANCE_ESCALATION_HOURS) has passed. The UPDATE ... RETURNING is the
    # claim, so two workers can never escalate the same grievance twice (UD-12).
    rows = db.all(
        f"""
        UPDATE grievances SET status = 'ESCALATED', escalated_at = NOW(), last_updated_at = NOW()
        WHERE id IN (
            SELECT id FROM grievances
            WHERE status IN ('NEW', 'IN_PROGRESS') AND due_date IS NOT NULL
              AND due_date + make_interval(hours => %s) < NOW()
            ORDER BY due_date
            LIMIT %s
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id, {pii.dec_sql("user_id_enc")} AS user_id, fiduciary_id, reference_number, language
        """,
        (settings.grievance_escalation_hours, settings.worker_batch_size, *db.bind_key()),
    )
    count = 0
    for row in rows:
        gid = str(row["id"])
        fid = str(row["fiduciary_id"])
        # GR-03: answered in the language the grievance was filed in.
        _notify(
            "PRINCIPAL",
            str(row["user_id"]),
            fid,
            "GRIEVANCE_ESCALATED",
            {"reference_number": row.get("reference_number"), "language": row.get("language")},
        )
        # GR-07: an escalation must reach the fiduciary's DPO too, not only the
        # complainant — the DPO owns the SLA and can reassign or drive the
        # overdue grievance to resolution.
        _notify("DPO", _dpo_recipient(fid), fid, "GRIEVANCE_ESCALATED")
        log_event(str(row["user_id"]), fid, "APP", None, "GRIEVANCE_ESCALATED", {"grievance_id": gid})
        count += 1
    return {"escalated": count}


def _retention_for(fiduciary_id: str, purpose_id: str) -> tuple[int | None, str | None]:
    """(retention_period_days, retention_start_event) for a closed purpose.

    P8-07: the lookup lives in services.retention (retention_for /
    retention_for_purposes) so request handlers do not reach into the jobs
    module; kept here for the sweep's existing call sites.
    """
    from .services.retention import retention_for

    return retention_for(fiduciary_id, purpose_id)


def _cessation_for(fiduciary_id: str, purpose_id: str) -> datetime | None:
    """Latest moment processing ceased for a purpose: purpose closure, else last withdrawal."""
    closed = db.one(
        "SELECT closed_at FROM purpose_lifecycle WHERE fiduciary_id = %s AND purpose_id = %s AND state = 'CLOSED'",
        (fiduciary_id, purpose_id),
    )
    if closed and closed.get("closed_at"):
        return closed["closed_at"]
    row = db.one(
        """
        SELECT MAX(cr.last_updated_at) AS cessation
        FROM consent_records cr,
             LATERAL jsonb_array_elements(cr.data_point_consents) AS p
        WHERE cr.fiduciary_id = %s
          AND lower(btrim(COALESCE(p ->> 'data_point_id', p ->> 'purpose_id', p ->> 'id'))) = lower(btrim(%s))
          AND (p ->> 'consent_granted' = 'false' OR lower(p ->> 'status') = 'withdrawn')
        """,
        (fiduciary_id, purpose_id),
    )
    return row["cessation"] if row else None


def _expiry_action(fiduciary_id: str, purpose_id: str) -> str:
    """PL-03: ERASE or DE_IDENTIFY for a purge raised at retention expiry — the
    retention policy's action_at_expiry, else the action chosen at closure."""
    from .services.retention import applicable_policy

    policy = applicable_policy(fiduciary_id, purpose_id)
    if policy and policy.get("action_at_expiry"):
        return str(policy["action_at_expiry"]).upper()
    row = db.one(
        "SELECT deidentification_action FROM purpose_lifecycle WHERE fiduciary_id = %s AND purpose_id = %s",
        (fiduciary_id, purpose_id),
    )
    return str((row or {}).get("deidentification_action") or "ERASE").upper()


def flag_overdue_purges() -> dict[str, int]:
    """SA-09: a purge the CMS orchestrated must be confirmed done. Requests still
    open past PURGE_COMPLETION_SLA_DAYS (and not under legal hold) are flagged to
    the DPO once, so an unconfirmed deletion never passes silently."""
    rows = db.all(
        """
        UPDATE purge_requests SET overdue_notified_at = NOW()
        WHERE id IN (
            SELECT id FROM purge_requests
            WHERE status IN ('PENDING', 'IN_PROGRESS', 'PURGE_IN_PROGRESS')
              AND overdue_notified_at IS NULL
              AND initiated_at < NOW() - make_interval(days => %s)
            LIMIT %s
            FOR UPDATE SKIP LOCKED
        )
        RETURNING id, fiduciary_id, purpose_id
        """,
        (settings.purge_completion_sla_days, settings.worker_batch_size),
    )
    for row in rows:
        fid = str(row["fiduciary_id"])
        _notify("DPO", _dpo_recipient(fid), fid, "PURGE_OVERDUE")
        log_event(
            "SYSTEM",
            fid,
            "SYSTEM",
            None,
            "PURGE_OVERDUE",
            {"purge_request_id": str(row["id"]), "purpose_id": row["purpose_id"]},
        )
    return {"flagged": len(rows)}


def release_expired_legal_holds() -> dict[str, int]:
    """CW-11: a legal hold lasts for the retention period it cites; once that
    ends the request becomes an ordinary pending purge."""
    released = db.execute(
        """
        UPDATE purge_requests SET status = 'PENDING', last_updated_at = NOW(),
               details = COALESCE(details || ' ', '') || '[legal hold expired]'
        WHERE status = 'LEGAL_HOLD_APPLIED' AND hold_until IS NOT NULL AND hold_until < NOW()
        """
    )
    return {"released": released or 0}


def prune_revoked_tokens() -> dict[str, int]:
    """SA-05: a revoked token only needs remembering until it would have expired anyway."""
    return {"pruned": db.execute("DELETE FROM revoked_tokens WHERE expires_at < NOW()") or 0}


def expire_lapsed_api_keys() -> dict[str, int]:
    """SEC-07: mark keys whose expires_at has passed as EXPIRED so the listing
    and the enforced behaviour (security.api_key_valid) always agree.

    Enforcement already rejects an expired key at authenticate time; until this
    sweep runs the console still shows such a key as ACTIVE, which is exactly
    the mismatch the finding called out.
    """
    updated = db.execute(
        "UPDATE api_keys SET status = 'EXPIRED', last_used_at = last_used_at"
        " WHERE status = 'ACTIVE' AND expires_at IS NOT NULL AND expires_at < NOW()"
    )
    return {"expired": updated or 0}


def prune_sso_nonces() -> dict[str, int]:
    """SEC-14: drop SSO login nonces past the token lifetime; a nonce can never
    be presented again once its id_token would have expired anyway."""
    return {"pruned": db.execute("DELETE FROM sso_login_nonces WHERE expires_at < NOW()") or 0}


# P5-07: Rule 6(1)(e) sets a ONE-YEAR floor on retaining logs and personal
# data. webhook_deliveries is the channel of record for consent events and OTP
# dispatch, so terminal rows may never be pruned faster than this floor, whatever
# WEBHOOK_DELIVERY_RETENTION_DAYS says. audit_logs and notification_deliveries
# are intentionally NEVER pruned by any sweep — audit_logs is append-only by
# trigger (db/19) and notification_deliveries now has a database-enforced
# one-year DELETE floor (db/23) — which satisfies the same floor by construction;
# that retention choice is stated here as policy, not an accident of the code.
RULE_6_1_E_MIN_RETENTION_DAYS = 365


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


def expire_nominations() -> dict[str, int]:
    """P6-07: sweep ACTIVE nominations whose valid_until has passed to EXPIRED.

    This makes valid_until actually mean something (a nomination dated 2030 is
    no longer returned as active today once 2030 arrives), and keeps the stored
    status in line with the effective status list_nominations already computes.
    """
    expired = db.execute(
        "UPDATE nominations SET status = 'EXPIRED', last_updated_at = NOW()"
        " WHERE status = 'ACTIVE' AND valid_until IS NOT NULL AND valid_until < NOW()"
    )
    return {"expired": expired or 0}


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


# Rule 6(1)(c): logs are only half the clause - something must watch them.
# A burst of failed sign-ins within the window raises an acknowledgeable alert
# and tells the DPO, at most once per window per fiduciary.
SECURITY_FAILURE_ACTIONS = ("LOGIN_FAILURE", "PRINCIPAL_LOGIN_FAILURE", "MFA_VERIFY_FAILED")
SECURITY_FAILURE_THRESHOLD = 20
SECURITY_WINDOW_MINUTES = 60


def flag_security_anomalies() -> dict[str, int]:
    """R6-c: alert on bursts of failed authentication, and on identifier reveal volume, recorded in the ledger."""
    from .services.lifecycle import record_alert

    bursts = db.all(
        """
        SELECT a.fiduciary_id, COUNT(*) AS failures
        FROM audit_logs a JOIN fiduciaries f ON f.id = a.fiduciary_id
        WHERE a.audit_action = ANY(%s)
          AND a.timestamp > (NOW() AT TIME ZONE 'UTC') - make_interval(mins => %s)
        GROUP BY a.fiduciary_id
        HAVING COUNT(*) >= %s
        """,
        (list(SECURITY_FAILURE_ACTIONS), SECURITY_WINDOW_MINUTES, SECURITY_FAILURE_THRESHOLD),
    )
    raised = 0
    for row in bursts:
        fid = str(row["fiduciary_id"])
        recent = db.one(
            "SELECT 1 FROM alerts WHERE fiduciary_id = %s AND alert_type = 'SECURITY_AUTH_FAILURE_BURST'"
            " AND created_at > NOW() - make_interval(mins => %s) LIMIT 1",
            (fid, SECURITY_WINDOW_MINUTES),
        )
        if recent:
            continue
        record_alert(
            fid,
            "SECURITY_AUTH_FAILURE_BURST",
            None,
            {"failures": int(row["failures"]), "window_minutes": SECURITY_WINDOW_MINUTES},
        )
        _notify(
            "DPO",
            _dpo_recipient(fid),
            fid,
            "SECURITY_AUTH_FAILURE_BURST",
            {"failures": int(row["failures"]), "window_minutes": SECURITY_WINDOW_MINUTES},
        )
        raised += 1
    raised += _flag_reveal_volume(record_alert)
    return {"alerts_raised": raised}


# P16-05: reveals of principal identifiers (PII_REVEALED) by one operator in one
# tenant above this many per window alert the DPO, once per window.
REVEAL_VOLUME_THRESHOLD = 50
REVEAL_VOLUME_WINDOW_MINUTES = 60


def _flag_reveal_volume(record_alert) -> int:
    from .services.pii import REVEAL_ACTION

    rows = db.all(
        """
        SELECT a.fiduciary_id, a.initiator, COUNT(*) AS reveals
        FROM audit_logs a JOIN fiduciaries f ON f.id = a.fiduciary_id
        WHERE a.audit_action = %s
          AND a.timestamp > (NOW() AT TIME ZONE 'UTC') - make_interval(mins => %s)
        GROUP BY a.fiduciary_id, a.initiator
        HAVING COUNT(*) >= %s
        """,
        (REVEAL_ACTION, REVEAL_VOLUME_WINDOW_MINUTES, REVEAL_VOLUME_THRESHOLD),
    )
    raised = 0
    for row in rows:
        fid = str(row["fiduciary_id"])
        operator = str(row["initiator"] or "")
        recent = db.one(
            "SELECT 1 FROM alerts WHERE fiduciary_id = %s AND alert_type = 'SECURITY_PII_REVEAL_VOLUME'"
            " AND event_ref_id = %s AND created_at > NOW() - make_interval(mins => %s) LIMIT 1",
            (fid, operator, REVEAL_VOLUME_WINDOW_MINUTES),
        )
        if recent:
            continue
        context = {"operator": operator, "reveals": int(row["reveals"]), "window_minutes": REVEAL_VOLUME_WINDOW_MINUTES}
        record_alert(fid, "SECURITY_PII_REVEAL_VOLUME", operator, context)
        _notify("DPO", _dpo_recipient(fid), fid, "SECURITY_PII_REVEAL_VOLUME", context)
        raised += 1
    return raised


# s.8(6) / Rule 7(2): the 72-hour Board intimation clock. A breach whose
# intimation is not recorded raises a DUE alert inside the last 12 hours and a
# MISSED alert once the deadline passes - each once per breach.
BREACH_DUE_WARNING_HOURS = 12


def flag_breach_board_deadlines() -> dict[str, int]:
    """S8-6: nothing watched board_notification_deadline."""
    from .services.lifecycle import record_alert

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


def run_retention_sweep() -> dict[str, int]:
    """PL-04 / SA-09 / SA-11: run the retention clock from cessation, independently of
    consent state, and warn administrators 48 hours before a scheduled deletion."""
    purposes = db.all("SELECT DISTINCT purpose_id, fiduciary_id FROM purpose_lifecycle WHERE state = 'CLOSED'")
    created = 0
    notices = 0
    for row in purposes:
        fid = str(row["fiduciary_id"])
        purpose_id = str(row["purpose_id"])
        retention_days, _start = _retention_for(fid, purpose_id)
        if not retention_days:
            continue
        cessation = _cessation_for(fid, purpose_id)
        if not cessation:
            cessation = datetime.now(UTC)
        due = cessation + timedelta(days=int(retention_days))
        window = (due - datetime.now(UTC)).total_seconds() / 3600.0
        if window <= 0:
            if _claim_pending_purges(fid, purpose_id, "RetentionPolicyExpiry"):
                rowcount = db.execute(
                    """
                    INSERT INTO purge_requests
                        (user_id_enc, user_id_hmac, fiduciary_id, purpose_id, trigger_event, details, action)
                    SELECT DISTINCT ON (cr.user_id_hmac)
                           cr.user_id_enc, cr.user_id_hmac, cr.fiduciary_id, %s, 'RetentionPolicyExpiry', %s, %s
                    FROM consent_records cr,
                         LATERAL jsonb_array_elements(cr.data_point_consents) AS p
                    WHERE cr.fiduciary_id = %s
                      AND lower(btrim(COALESCE(p ->> 'data_point_id', p ->> 'purpose_id', p ->> 'id'))) = lower(btrim(%s))
                      AND NOT EXISTS (
                            SELECT 1 FROM purge_requests pr
                            WHERE pr.user_id_hmac = cr.user_id_hmac
                              AND pr.fiduciary_id = cr.fiduciary_id
                              AND pr.purpose_id = %s
                              AND pr.trigger_event = 'RetentionPolicyExpiry'
                              AND pr.status IN ('PENDING', 'IN_PROGRESS')
                          )
                    """,
                    (
                        purpose_id,
                        f"Retention period of {retention_days} days elapsed from cessation {due.isoformat()} (PL-04).",
                        _expiry_action(fid, purpose_id),
                        fid,
                        purpose_id,
                        purpose_id,
                    ),
                )
                created += rowcount or 0
                _notify("DPO", _dpo_recipient(fid), fid, "PURGE_EXECUTED")
        elif window <= float(settings.purge_notice_hours):
            existing = db.one(
                f"""
                SELECT 1 FROM notifications
                WHERE fiduciary_id = %s AND notification_type = 'PURGE_SCHEDULED'
                  AND {pii.match_sql("recipient_id")} AND created_at > NOW() - INTERVAL '24 hours'
                LIMIT 1
                """,
                (fid, *pii.hmac_params(_dpo_recipient(fid))),
            )
            if not existing:
                _notify("DPO", _dpo_recipient(fid), fid, "PURGE_SCHEDULED")
                notices += 1
                log_event(
                    "SYSTEM",
                    fid,
                    "SYSTEM",
                    None,
                    "PURGE_SCHEDULED",
                    {"purpose_id": purpose_id, "due": due.isoformat(), "notice_hours": settings.purge_notice_hours},
                )
    return {"purge_requests_created": created, "admin_notices": notices}


_CSV_SUBSCRIPTIONS: dict[str, tuple[str, str, str]] = {
    # subtype -> (table, default_columns, date_column)
    "CONSENT": ("consent_records", "id,user_id,policy_id,policy_version,consent_status_general,timestamp", "timestamp"),
    "PRINCIPAL": (
        "data_principal",
        "user_id,fiduciary_id,last_consent_mechanism,age_category,created_at",
        "created_at",
    ),
    "GRIEVANCE": ("grievances", "id,user_id,type,subject,status,submission_timestamp", "submission_timestamp"),
    # P9-08 / LG-07: every hashed column plus both hashes and the hash version,
    # so whoever receives the export can re-verify the chain it came from.
    "AUDIT": (
        "audit_logs",
        "id,fiduciary_id,timestamp,user_id,service_type,service_id,audit_action,context_details,"
        "purpose_id,consent_status,initiator,source_ip,prev_log_hash,current_log_hash,system_metadata",
        "timestamp",
    ),
}
# Export columns holding a principal id: stored as <col>_enc/<col>_hmac (db/34),
# decrypted for the export and written masked - every export job is operator
# requested. audit_logs.user_id is already a pseudonym and is not listed.
_CSV_PRINCIPAL_COLUMNS = {"CONSENT": {"user_id"}, "PRINCIPAL": {"user_id"}, "GRIEVANCE": {"user_id"}}


def execute_queued_jobs() -> dict[str, int]:
    """LG-07: run PENDING jobs — EXPORT subtypes write CSV files; CES runs the
    time-bound purpose closure for the fiduciary. This replaces the queue that
    previously never executed."""
    rows = db.all(
        """
        SELECT id, fiduciary_id, job_type, subtype, start_date, end_date, input_payload
        FROM jobs WHERE status = 'PENDING' ORDER BY created_at LIMIT %s
        """,
        (settings.worker_batch_size,),
    )
    completed = failed = 0
    for row in rows:
        job_id = str(row["id"])
        if (
            db.execute(
                "UPDATE jobs SET status = 'RUNNING', started_at = NOW() WHERE id = %s AND status = 'PENDING'",
                (job_id,),
            )
            != 1
        ):
            continue
        job_type = str(row["job_type"] or "").upper()
        subtype = str(row["subtype"] or "").upper()
        try:
            if job_type == "CES":
                close_due_time_bound_purposes()
                db.execute("UPDATE jobs SET status = 'COMPLETED', completed_at = NOW() WHERE id = %s", (job_id,))
                completed += 1
                continue
            if job_type == "EXPORT" and subtype in _CSV_SUBSCRIPTIONS:
                path = _write_export(row)
                db.execute(
                    "UPDATE jobs SET status = 'COMPLETED', completed_at = NOW(), output_file_path = %s WHERE id = %s",
                    (str(path), job_id),
                )
                completed += 1
                continue
            db.execute(
                "UPDATE jobs SET status = 'FAILED', completed_at = NOW(), error_message = %s WHERE id = %s",
                (f"Unsupported job: {job_type}/{subtype}", job_id),
            )
            failed += 1
        except Exception as exc:  # noqa: BLE001
            log.exception("Job %s failed", job_id)
            db.execute(
                "UPDATE jobs SET status = 'FAILED', completed_at = NOW(), error_message = %s WHERE id = %s",
                (str(exc)[:500], job_id),
            )
            failed += 1
    return {"completed": completed, "failed": failed}


def _write_export(job: dict[str, Any]) -> Path:
    subtype = str(job["subtype"]).upper()
    table, columns, date_column = _CSV_SUBSCRIPTIONS[subtype]
    principal_columns = _CSV_PRINCIPAL_COLUMNS.get(subtype, set())
    fieldnames = [col.strip() for col in columns.split(",")]
    select = ", ".join(
        f"{pii.dec_sql(f'{col}_enc')} AS {col}" if col in principal_columns else col for col in fieldnames
    )
    where = ["fiduciary_id = %s"]
    params: list[Any] = [*(db.bind_key() * len(principal_columns)), str(job["fiduciary_id"])]
    if job.get("start_date"):
        where.append(f"{date_column} >= %s::date")
        params.append(job["start_date"])
    if job.get("end_date"):
        # Exclusive upper bound: the whole end_date, and exactly the window the
        # AUDIT chain verdict below examines (P10-06).
        where.append(f"{date_column} < %s::date + INTERVAL '1 day'")
        params.append(job["end_date"])
    if subtype == "AUDIT":
        # The whole ledger, archived years included: the chain verdict below
        # covers them, so the file must too.
        from .audit import ledger_source

        table = ledger_source()
    rows = db.all(f"SELECT {select} FROM {table} WHERE {' AND '.join(where)} ORDER BY {date_column} DESC", params)
    for row in rows:
        for col in principal_columns:
            row[col] = pii.mask(row[col])
    output_dir = settings.export_path
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"job_{job['id']}_{str(job['subtype']).lower()}.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        # PT-02: neutralise formula cells - except in the AUDIT export, whose
        # cells must stay byte-exact so every row hash recomputes from the file
        # (P9-08). Open that file as text data, never as a live spreadsheet.
        audit = str(job["subtype"]).upper() == "AUDIT"
        for row in rows:
            writer.writerow(
                {key: _csv_value(value) if audit else csv_safe(_csv_value(value)) for key, value in row.items()}
            )
    context: dict[str, Any] = {"output_file_path": str(path), "rows": len(rows)}
    if str(job["subtype"]).upper() == "AUDIT":
        # P9-08: ship the chain verdict for the exported range with the file.
        # P10-06: the verdict covers exactly the exported window - bounded by
        # end_date as well as start_date - and attests an intact chain ONLY
        # when every row of that window was examined. A truncated walk that
        # found nothing broken proves nothing, so it never reads as intact.
        from .audit import verify_chain

        since = _day_start(job.get("start_date"))
        until = _day_start(job.get("end_date"), plus_days=1)
        verdict = verify_chain(fiduciary_id=str(job["fiduciary_id"]), since=since, until=until)
        attested = bool(verdict.get("intact")) and bool(verdict.get("coverage_complete"))
        verdict = {
            **verdict,
            "chain_intact": attested,
            "attestation": "INTACT"
            if attested
            else ("BROKEN" if verdict.get("broken_count") or verdict.get("foreign_broken_count") else "NOT_ATTESTED"),
            "export_window": {"start_date": job.get("start_date"), "end_date": job.get("end_date")},
        }
        verdict_path = path.with_suffix(".verification.json")
        verdict_path.write_text(json.dumps(db.to_jsonable(verdict), indent=2, default=str), encoding="utf-8")
        context["chain_intact"] = attested
        context["chain_coverage_complete"] = bool(verdict.get("coverage_complete"))
        context["chain_verification_path"] = str(verdict_path)
    log_event(
        "SYSTEM",
        str(job["fiduciary_id"]),
        "SYSTEM",
        str(job["id"]),
        "JOB_COMPLETED",
        context,
    )
    return path


def _day_start(value: Any, plus_days: int = 0) -> datetime | None:
    """Midnight UTC of a job's start_date / end_date (a date or ISO string)."""
    if not value:
        return None
    day = value if hasattr(value, "year") else datetime.fromisoformat(str(value)[:10])
    start = datetime(day.year, day.month, day.day, tzinfo=UTC)
    return start + timedelta(days=plus_days)


def _csv_value(value: Any) -> Any:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return value
