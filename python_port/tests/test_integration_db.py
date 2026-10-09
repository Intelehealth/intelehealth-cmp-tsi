"""Integration tests against a REAL Postgres.

The workbook's root-cause finding (CF-03 / P6/P7) is that the unit suite stubs
the database, so scoping and ordering defects are invisible. These tests run
the actual SQL against the provisioned schema. They SKIP when no database is
reachable, so the local unit suite stays fast and green; CI provisions Postgres
and applies db/*.sql before pytest, so they exercise the real thing there.

Use them for the exact classes that kept regressing:
  * erasure / de-identification scoping (the P6-06 and P7-01 classes)
  * the hash-chain verifier against real rows (P6-01 / SEC-10)
"""

import contextlib
import uuid

import psycopg
import pytest

try:
    from dpdpcms_py import db as real_db
    from dpdpcms_py.config import settings
    from dpdpcms_py.services.compliance import deidentify_purpose_cms_copy

    _DB_READY = False
    try:
        with psycopg.connect(settings.db_dsn, connect_timeout=3) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        _DB_READY = True
    except Exception:  # pragma: no cover - only probe connectivity
        _DB_READY = False
except Exception:  # pragma: no cover
    real_db = None
    settings = None
    deidentify_purpose_cms_copy = None
    _DB_READY = False


pytestmark = pytest.mark.skipif(not _DB_READY, reason="no live Postgres configured")


def _fid():
    return str(uuid.uuid4())


def _scoped_connection():
    @contextlib.contextmanager
    def conn_cm():
        with psycopg.connect(settings.db_dsn) as conn:
            yield conn

    return conn_cm


def test_erasure_deidentify_scopes_to_the_principal():
    """P7-01 regression: de-identifying a purpose for ONE principal must not
    touch another principal's consent records in the same tenant."""
    fid = _fid()
    purpose = "care"
    conn_cm = _scoped_connection()
    with conn_cm() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, "
            " data_point_consents, is_active_consent, jurisdiction, consent_status_general, consent_mechanism, "
            " ip_address, created_at, last_updated_at) "
            "VALUES (uuid_generate_v4(), %s, %s, 'p1', 'v1', NOW(), %s, TRUE, 'IN', 'CONSENT_GIVEN', 'WEB', "
            " '1.2.3.4', NOW(), NOW())",
            (
                "asha",
                fid,
                real_db.as_jsonb(
                    [{"data_point_id": purpose, "purpose_agreed_to": "Care", "consent_granted": True}]
                ),
            ),
        )
        cur.execute(
            "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, "
            " data_point_consents, is_active_consent, jurisdiction, consent_status_general, consent_mechanism, "
            " ip_address, created_at, last_updated_at) "
            "VALUES (uuid_generate_v4(), %s, %s, 'p1', 'v1', NOW(), %s, TRUE, 'IN', 'CONSENT_GIVEN', 'WEB', "
            " '1.2.3.5', NOW(), NOW())",
            (
                "ramesh",
                fid,
                real_db.as_jsonb(
                    [{"data_point_id": purpose, "purpose_agreed_to": "Care", "consent_granted": True}]
                ),
            ),
        )
        conn.commit()

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(real_db, "connection", conn_cm)
    try:
        deidentify_purpose_cms_copy(fid, "asha", purpose, action="ERASE")
    finally:
        monkeypatch.undo()

    with conn_cm() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT user_id, data_point_consents FROM consent_records WHERE fiduciary_id = %s ORDER BY user_id",
            (fid,),
        )
        rows = {r["user_id"]: r["data_point_consents"] for r in cur.fetchall()}
    # asha's entry was dropped (ERASE), ramesh's must be untouched.
    assert all(p.get("data_point_id") != purpose for p in rows["asha"])
    assert any(p.get("data_point_id") == purpose for p in rows["ramesh"]), (
        "P7-01: de-identification leaked across the tenant"
    )


def test_erasure_metadata_scrub_runs_on_the_original_user_id():
    """P6-06 regression against a real DB: the consent-record metadata scrub
    must actually clear ip/user_agent rather than match nothing after re-keying."""
    fid = _fid()
    conn_cm = _scoped_connection()
    with conn_cm() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, "
            " data_point_consents, is_active_consent, jurisdiction, consent_status_general, consent_mechanism, "
            " ip_address, user_agent, created_at, last_updated_at) "
            "VALUES (uuid_generate_v4(), %s, %s, 'p1', 'v1', NOW(), %s, TRUE, 'IN', 'CONSENT_GIVEN', 'WEB', "
            " '9.9.9.9', 'curl/8', NOW(), NOW())",
            (
                "asha",
                fid,
                real_db.as_jsonb([{"data_point_id": "care", "consent_granted": True}]),
            ),
        )
        conn.commit()

    from dpdpcms_py.services.compliance import erase_cms_copy

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(real_db, "connection", conn_cm)
    try:
        erase_cms_copy(fid, "asha")
    finally:
        monkeypatch.undo()

    with conn_cm() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT ip_address, user_agent FROM consent_records WHERE fiduciary_id = %s AND user_id LIKE 'erased:%'",
            (fid,),
        )
        row = cur.fetchone()
    assert row is not None
    assert row["ip_address"] == "0.0.0.0"
    assert row["user_agent"] is None


def test_chain_verifies_intact_and_detects_tampering_on_real_rows():
    """P6-01 / SEC-10: the hash-chain verifier must pass on an intact ledger and
    flag a tampered row when both are real rows."""
    from dpdpcms_py import audit

    fid = _fid()
    with psycopg.connect(settings.db_dsn) as conn:
        with conn.cursor() as cur:
            for i in range(3):
                audit.log_event(
                    "asha",
                    fid,
                    "APP",
                    None,
                    f"TEST_ACTION_{i}",
                    {"n": i},
                    purpose_id="care",
                    source_ip="9.9.9.9",
                )
        conn.commit()

    # audit.log_event / verify_chain open their own connections from settings,
    # so no monkeypatching is needed — these run against the real ledger.
    result = audit.verify_chain(limit=100, fiduciary_id=fid)
    assert result["intact"] is True
    assert result["rows_checked"] >= 3

    with psycopg.connect(settings.db_dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE audit_logs SET context_details = 'tampered' WHERE fiduciary_id = %s ORDER BY timestamp DESC LIMIT 1",
            (fid,),
        )
        conn.commit()
    broken = audit.verify_chain(limit=100, fiduciary_id=fid)
    assert broken["intact"] is False, "tampering must be detected"
    assert any(b["reason"] == "CONTENT_MISMATCH" for b in broken["broken"])