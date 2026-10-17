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
