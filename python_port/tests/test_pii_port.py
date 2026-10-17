"""Ports of Consent-Manager's PII and audit features.

DB-backed tests reuse the transaction-per-test fixture and seed helpers of
test_integration_db.py and skip without a live Postgres; the rest are unit
tests.
"""

import pytest
from tests.test_integration_db import _DB_READY, _ctx, _seed_tenant

needs_db = pytest.mark.skipif(not _DB_READY, reason="no live Postgres configured")

FID = "11111111-1111-1111-1111-111111111111"


# ---- Task 1: grievance channel -----------------------------------------------------


def _capture_submit(monkeypatch, ctx):
    """Run submit_grievance with the DB stubbed; return the channel it inserted."""
    from dpdpcms_py.services import compliance as compliance_mod

    inserted = []

    def fake_insert(sql, params=()):
        inserted.append((sql, params))
        return {"id": "g1", "reference_number": "GRV-2026-ABC123"}

    monkeypatch.setattr(compliance_mod, "resolve_fiduciary", lambda c: FID)
    monkeypatch.setattr(compliance_mod.db, "one", lambda sql, params=(): None)
    monkeypatch.setattr(compliance_mod.db, "insert_returning", fake_insert)
    monkeypatch.setattr(compliance_mod.db, "execute", lambda sql, params=(): 1)
    monkeypatch.setattr(compliance_mod, "log_event", lambda *a, **k: None)
    compliance_mod.GrievanceService().submit_grievance(ctx)
    sql, params = inserted[0]
    assert "channel" in sql
    return params[-1]


def _payload(**extra):
    return {"user_id": "asha", "type": "GENERAL_COMPLAINT", "subject": "s", "description": "d", **extra}


def test_grievance_channel_defaults_to_portal_for_principal_and_api_callers(monkeypatch):
    from dpdpcms_py.context import RequestContext

    def ctx(**extra):
        return RequestContext(
            path="/api/v1/grievance",
            category="client",
            service="grievance",
            payload=_payload(channel="EMAIL"),
            headers={},
            fiduciary_id=FID,
            **extra,
        )

    assert _capture_submit(monkeypatch, ctx(auth_via_principal_jwt=True, principal_user_id="asha")) == "PORTAL"
    assert _capture_submit(monkeypatch, ctx(app_id="app-1")) == "PORTAL"
    assert _capture_submit(monkeypatch, ctx()) == "PORTAL"


def test_dpo_can_log_offline_grievance_with_channel(monkeypatch):
    from dpdpcms_py.errors import ApiError

    ctx = _ctx(FID, _payload(channel="PHONE"), operator_id="op-1")
    assert _capture_submit(monkeypatch, ctx) == "PHONE"
    # An operator who names no channel gets the default.
    assert _capture_submit(monkeypatch, _ctx(FID, _payload(), operator_id="op-1")) == "PORTAL"
    with pytest.raises(ApiError) as err:
        _capture_submit(monkeypatch, _ctx(FID, _payload(channel="FAX"), operator_id="op-1"))
    assert err.value.status == 400


@needs_db
def test_grievance_channel_column_defaults_portal(tx):
    import psycopg

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO grievances (id, user_id, fiduciary_id, type, subject, description, status)"
            " VALUES (uuid_generate_v4(), 'asha', %s, 'GENERAL_COMPLAINT', 's', 'd', 'NEW') RETURNING channel",
            (fid,),
        )
        assert cur.fetchone()["channel"] == "PORTAL"
        with pytest.raises(psycopg.errors.CheckViolation), tx.transaction():
            cur.execute("UPDATE grievances SET channel = 'FAX' WHERE fiduciary_id = %s", (fid,))


def test_operator_logged_grievance_is_audited_as_the_operator(monkeypatch):
    from dpdpcms_py.services import compliance as compliance_mod

    events = []
    _capture_submit(monkeypatch, _ctx(FID, _payload(), operator_id="op-1"))  # installs the DB stubs
    monkeypatch.setattr(compliance_mod, "log_event", lambda *a, **k: events.append(k))
    compliance_mod.GrievanceService().submit_grievance(_ctx(FID, _payload(channel="PHONE"), operator_id="op-1"))
    compliance_mod.GrievanceService().submit_grievance(_ctx(FID, _payload()))
    assert events[0]["initiator"] == "OPERATOR:op-1"
    assert events[1]["initiator"] == "INTEGRATOR"


# ---- Task 2: yearly audit partitions + archive ---------------------------------------


def _log_at(monkeypatch, when, action="TEST_EVENT", fid=None):
    """log_event with the audit clock pinned to `when` (naive UTC)."""
    from datetime import UTC

    from dpdpcms_py import audit

    monkeypatch.setattr(audit, "_now", lambda: when.replace(tzinfo=UTC))
    audit.log_event("asha", fid, "SYSTEM", None, action, {"t": when.isoformat()})


def _regclass(cur, name):
    cur.execute("SELECT to_regclass(%s) AS r", (f"public.{name}",))
    return cur.fetchone()["r"]


def _live_partition_years(cur):
    import re

    cur.execute(
        "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid"
        " WHERE i.inhparent = 'public.audit_logs'::regclass"
    )
    return sorted(int(m.group(1)) for r in cur.fetchall() if (m := re.fullmatch(r"audit_logs_y(\d{4})", r["relname"])))


@needs_db
def test_audit_logs_is_partitioned_with_default(tx):
    with tx.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_partitioned_table WHERE partrelid = 'public.audit_logs'::regclass")
        assert cur.fetchone(), "audit_logs is not partitioned"
        cur.execute(
            "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid"
            " WHERE i.inhparent = 'public.audit_logs'::regclass"
            " AND pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT'"
        )
        assert cur.fetchone()["relname"] == "audit_logs_default"
        assert _live_partition_years(cur), "no yearly partitions"


@needs_db
def test_default_partition_catches_unplanned_year(tx, monkeypatch):
    from datetime import datetime

    _log_at(monkeypatch, datetime(2099, 12, 31, 23, 59, 59))
    with tx.cursor() as cur:
        cur.execute("SELECT tableoid::regclass::text AS part FROM audit_logs WHERE timestamp >= '2099-01-01'")
        assert cur.fetchone()["part"] == "audit_logs_default"


@needs_db
def test_append_only_triggers_apply_to_partitions(tx):
    import psycopg
    from dpdpcms_py import audit

    audit.log_event("asha", None, "SYSTEM", None, "TEST_EVENT", {})
    with tx.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege), tx.transaction():
            cur.execute("UPDATE audit_logs SET audit_action = 'X'")
        with pytest.raises(psycopg.errors.InsufficientPrivilege), tx.transaction():
            cur.execute("DELETE FROM audit_logs")
        for part in [f"audit_logs_y{y}" for y in _live_partition_years(cur)] + ["audit_logs_default"]:
            with pytest.raises(psycopg.errors.InsufficientPrivilege), tx.transaction():
                cur.execute(f"TRUNCATE {part}")


@needs_db
def test_archive_sweep_detaches_old_years_and_chain_still_verifies(tx, monkeypatch):
    import dataclasses
    from datetime import UTC, datetime

    import psycopg
    from dpdpcms_py import audit, jobs

    monkeypatch.setattr(jobs, "settings", dataclasses.replace(jobs.settings, audit_live_years=3))
    with tx.cursor() as cur:
        year = _live_partition_years(cur)[0]
    _log_at(monkeypatch, datetime(year, 3, 1))
    _log_at(monkeypatch, datetime(year, 3, 2))
    _log_at(monkeypatch, datetime(year + 2, 3, 1))
    with tx.cursor() as cur:
        cur.execute("SELECT id FROM audit_logs WHERE timestamp < %s ORDER BY timestamp", (datetime(year + 1, 1, 1),))
        old_ids = [str(r["id"]) for r in cur.fetchall()]
    assert len(old_ids) == 2, "seeded rows did not land in the oldest year (ledger has newer committed rows?)"

    now = datetime(year + 4, 6, 1, tzinfo=UTC)
    result = jobs.archive_audit_partitions(now)
    assert result["archived"] >= 1

    archive = f"audit_logs_y{year}_archive"
    with tx.cursor() as cur:
        assert _regclass(cur, archive) == archive
        assert _regclass(cur, f"audit_logs_y{year + 4}") == f"audit_logs_y{year + 4}"
        assert _regclass(cur, f"audit_logs_y{year + 5}") == f"audit_logs_y{year + 5}"
        assert year not in _live_partition_years(cur)
        assert year + 2 in _live_partition_years(cur)
        cur.execute(
            "SELECT row_count, period_start FROM audit_log_archive_registry WHERE partition_name = %s", (archive,)
        )
        reg = cur.fetchone()
        assert reg["row_count"] == 2 and reg["period_start"] == datetime(year, 1, 1)
        cur.execute("SELECT count(*) AS n FROM audit_logs WHERE id = ANY(%s::uuid[])", (old_ids,))
        assert cur.fetchone()["n"] == 0
        # The archived table is still append-only.
        with pytest.raises(psycopg.errors.InsufficientPrivilege), tx.transaction():
            cur.execute(f"DELETE FROM {archive}")
        with pytest.raises(psycopg.errors.InsufficientPrivilege), tx.transaction():
            cur.execute(f"TRUNCATE {archive}")

    # Readers span the archive: the chain verifies across the boundary and an
    # archived row is still found.
    chain = audit.verify_chain()
    assert chain["intact"] is True and chain["rows_checked"] >= 3
    assert str(audit.get_log(old_ids[0])["id"]) == old_ids[0]
    assert {str(r["id"]) for r in audit.list_logs({"user_id": "asha", "limit": 10})} >= set(old_ids)
    # A second run finds nothing more to do.
    assert jobs.archive_audit_partitions(now) == {"created": 0, "archived": 0}


def test_ledger_source_rejects_unexpected_registry_names(monkeypatch):
    from dpdpcms_py import audit

    monkeypatch.setattr(
        audit.db,
        "all",
        lambda *a, **k: [
            {"partition_name": "x; DROP TABLE audit_logs"},
            {"partition_name": "audit_logs_y2023_archive"},
        ],
    )
    source = audit.ledger_source()
    assert "DROP" not in source
    assert "audit_logs_y2023_archive" in source
    assert source.endswith("AS audit_logs")

    monkeypatch.setattr(audit.db, "all", lambda *a, **k: [{"partition_name": "x; DROP"}])
    assert audit.ledger_source() == "audit_logs"
