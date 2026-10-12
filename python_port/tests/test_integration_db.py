"""Integration tests against a REAL Postgres.

The workbook's root-cause finding (CF-03 / P6/P7) is that the unit suite stubs
the database, so scoping and ordering defects are invisible. These tests run
the actual SQL against the provisioned schema. They SKIP when no database is
reachable, so the local unit suite stays fast and green; CI provisions Postgres
and applies db/*.sql before pytest, so they exercise the real thing there.

Use them for the exact classes that kept regressing:
  * erasure / de-identification scoping (the P6-06, P7-01 and P8-01 classes),
    including a second tenant
  * purge-status ordering against the legal hold (P8-02)
  * the hash-chain verifier and certificates against real rows (P6-01, SEC-10,
    P7-02, P8-04, P6-12)
  * the Rule 6(1)(e) floor triggers of db/23 and db/24 (P7-04, P8-03)

P8-06: every test runs inside ONE transaction that is rolled back afterwards
(the `tx` fixture), so nothing a test seeds — and no tamper it performs on the
append-only ledger — survives into the shared database.
"""

import contextlib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row

try:
    from dpdpcms_py import db as real_db
    from dpdpcms_py.config import settings

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
    _DB_READY = False


pytestmark = pytest.mark.skipif(not _DB_READY, reason="no live Postgres configured")

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def tx(monkeypatch):
    """One connection, one transaction, rolled back at teardown (P8-06).

    db.connection() is patched to hand out this same connection, so service
    code — which opens "its own" connection per statement — runs inside the
    test's transaction and never commits.
    """
    conn = psycopg.connect(settings.db_dsn, row_factory=dict_row)
    if settings.db_encryption_key:
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.enc_key', %s, false)", (settings.db_encryption_key,))

    @contextlib.contextmanager
    def shared():
        # A savepoint per block: a service block that raises rolls back its own
        # writes, as db.connection() does in production, while the outer
        # transaction still discards everything at teardown.
        with conn.transaction():
            yield conn

    monkeypatch.setattr(real_db, "connection", shared)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


def _ctx(fid, payload, **extra):
    from dpdpcms_py.context import RequestContext

    return RequestContext(
        path="/api/v1/admin/test",
        category="admin",
        service="test",
        payload=payload,
        headers={},
        fiduciary_id=fid,
        auth_token={"email": "dpo@example.org", "role": "DPO"},
        **extra,
    )


def _seed_tenant(cur, purposes=("care",)):
    fid = str(uuid.uuid4())
    pol = f"pol-{fid[:8]}"
    cur.execute(
        "INSERT INTO fiduciaries (id, name, primary_domain, status) VALUES (%s, %s, %s, 'ACTIVE')",
        (fid, f"fid-{fid[:8]}", f"domain-{fid[:8]}.example"),
    )
    cur.execute(
        "INSERT INTO consent_policies (id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content)"
        " VALUES (%s, 'v1', %s, NOW(), 'ACTIVE', 'IN', %s)",
        (
            pol,
            fid,
            real_db.as_jsonb(
                {"en": {"title": "P", "data_processing_purposes": [{"id": p, "name": p} for p in purposes]}}
            ),
        ),
    )
    return fid, pol


def _seed_consent(cur, fid, pol, user, purposes=("care",), ip="1.2.3.4", user_agent=None):
    cur.execute(
        "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp, "
        " jurisdiction, language_selected, data_point_consents, is_active_consent, "
        " consent_status_general, consent_mechanism, ip_address, user_agent, created_at, last_updated_at) "
        "VALUES (uuid_generate_v4(), %s, %s, %s, 'v1', NOW(), 'IN', 'en', %s, TRUE, "
        " 'CONSENT_GIVEN', 'WEB', %s, %s, NOW(), NOW())",
        (
            user,
            fid,
            pol,
            real_db.as_jsonb(
                [{"data_point_id": p, "purpose_agreed_to": p.title(), "consent_granted": True} for p in purposes]
            ),
            ip,
            user_agent,
        ),
    )


def _consents(cur, fid):
    cur.execute(
        "SELECT user_id, data_point_consents FROM consent_records WHERE fiduciary_id = %s ORDER BY user_id", (fid,)
    )
    return {r["user_id"]: r["data_point_consents"] for r in cur.fetchall()}


# ── erasure / de-identification scoping ─────────────────────────────────────
def test_erasure_deidentify_scopes_to_the_principal(tx):
    """P7-01 regression: de-identifying a purpose for ONE principal must not
    touch another principal's consent records in the same tenant."""
    from dpdpcms_py.services.compliance import deidentify_purpose_cms_copy

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        _seed_consent(cur, fid, pol, "ramesh", ip="1.2.3.5")

        deidentify_purpose_cms_copy(fid, "asha", "care", action="ERASE")

        rows = _consents(cur, fid)
    assert all(p.get("data_point_id") != "care" for p in rows["asha"])
    assert any(p.get("data_point_id") == "care" for p in rows["ramesh"]), (
        "P7-01: de-identification leaked across the tenant"
    )


def test_deidentify_branch_runs_and_scopes_to_the_principal(tx):
    """P8-01: the DE_IDENTIFY branch used to raise IndeterminateDatatype (the
    pseudonym marker went untyped into jsonb_build_object). It must run, blank
    the entry for the one principal, keep the other purposes, and leave every
    other principal untouched."""
    from dpdpcms_py.services.compliance import deidentify_purpose_cms_copy

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("care", "research"))
        _seed_consent(cur, fid, pol, "asha", purposes=("care", "research"))
        _seed_consent(cur, fid, pol, "ramesh", purposes=("care", "research"))

        touched = deidentify_purpose_cms_copy(fid, "asha", "research", action="DE_IDENTIFY")

        rows = _consents(cur, fid)
    assert touched == {"consent_records_touched": 1}
    asha = {p["data_point_id"]: p for p in rows["asha"]}
    assert "care" in asha and asha["care"]["consent_granted"] is True
    blanked = [p for p in rows["asha"] if p.get("status") == "de_identified"]
    assert len(blanked) == 1
    assert blanked[0]["data_point_id"].startswith("erased:")
    assert blanked[0]["purpose_agreed_to"] == "[erased]"
    assert blanked[0]["consent_granted"] is False
    assert {p["data_point_id"] for p in rows["ramesh"]} == {"care", "research"}


def test_deidentification_and_erasure_never_cross_tenants(tx):
    """CF-03: a second tenant holding the SAME user id and purpose is untouched
    by a purpose de-identification or a whole-account erasure in the first."""
    from dpdpcms_py.services.compliance import deidentify_purpose_cms_copy, erase_cms_copy

    with tx.cursor() as cur:
        fid_a, pol_a = _seed_tenant(cur)
        fid_b, pol_b = _seed_tenant(cur)
        _seed_consent(cur, fid_a, pol_a, "asha")
        _seed_consent(cur, fid_b, pol_b, "asha", ip="5.6.7.8")

        deidentify_purpose_cms_copy(fid_a, "asha", "care", action="DE_IDENTIFY")
        erase_cms_copy(fid_a, "asha")

        b_rows = _consents(cur, fid_b)
        cur.execute("SELECT ip_address FROM consent_records WHERE fiduciary_id = %s", (fid_b,))
        b_ip = cur.fetchone()["ip_address"]
        a_users = set(_consents(cur, fid_a))
    assert list(b_rows) == ["asha"], "tenant B's principal was re-keyed by tenant A's erasure"
    assert b_rows["asha"][0]["data_point_id"] == "care"
    assert str(b_ip) == "5.6.7.8"
    assert all(user.startswith("erased:") for user in a_users)


def test_erasure_metadata_scrub_runs_on_the_original_user_id(tx):
    """P6-06 regression against a real DB: the consent-record metadata scrub
    must actually clear ip/user_agent rather than match nothing after re-keying."""
    from dpdpcms_py.services.compliance import erase_cms_copy

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha", ip="9.9.9.9", user_agent="curl/8")

        erase_cms_copy(fid, "asha")

        cur.execute(
            "SELECT ip_address, user_agent FROM consent_records WHERE fiduciary_id = %s AND user_id LIKE 'erased:%%'",
            (fid,),
        )
        row = cur.fetchone()
    assert row is not None
    assert str(row["ip_address"]) == "0.0.0.0"
    assert row["user_agent"] is None


# ── P8-02: purge status vs. the legal hold ───────────────────────────────────
def _seed_purge(cur, fid, user, purpose, status="PENDING", action="ERASE", hold_until=None, trigger="PurposeClosure"):
    cur.execute(
        "INSERT INTO purge_requests (user_id, fiduciary_id, purpose_id, trigger_event, status, action, hold_until)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
        (user, fid, purpose, trigger, status, action, hold_until),
    )
    return str(cur.fetchone()["id"])


def test_purpose_purge_under_legal_hold_is_refused_before_anything_is_written(tx):
    """P8-02: the hold refusal used to run AFTER the status UPDATE committed, so
    a held request was recorded PURGE_COMPLETED with nothing de-identified and
    no audit event. Now nothing is written; once the hold is gone, the same
    confirmation completes, de-identifies, and is audited."""
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.compliance import ComplianceService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("care", "research"))
        _seed_consent(cur, fid, pol, "asha", purposes=("care", "research"))
        request_id = _seed_purge(cur, fid, "asha", "research", action="DE_IDENTIFY")
        hold_id = _seed_purge(
            cur, fid, "asha", "ALL", status="LEGAL_HOLD_APPLIED", hold_until=datetime.now(UTC) + timedelta(days=30)
        )
        ctx = _ctx(fid, {"id": request_id, "status": "PURGE_COMPLETED"})

        with pytest.raises(ApiError) as exc:
            ComplianceService().update_purge_status(ctx)
        assert exc.value.status == 409

        cur.execute("SELECT status, completed_at FROM purge_requests WHERE id = %s", (request_id,))
        row = cur.fetchone()
        assert row["status"] == "PENDING", "P8-02: a refused request must not be recorded complete"
        assert row["completed_at"] is None
        assert any(p["data_point_id"] == "research" for p in _consents(cur, fid)["asha"])

        # Lift the hold: the same confirmation now completes end to end.
        cur.execute("UPDATE purge_requests SET status = 'COMPLETED' WHERE id = %s", (hold_id,))
        out = ComplianceService().update_purge_status(ctx)
        assert out["status"] == "PURGE_COMPLETED"
        assert out["cms_copy_erased"] == {"consent_records_touched": 1}
        cur.execute("SELECT status, completed_at FROM purge_requests WHERE id = %s", (request_id,))
        row = cur.fetchone()
        assert row["status"] == "PURGE_COMPLETED" and row["completed_at"] is not None
        assert not any(p["data_point_id"] == "research" for p in _consents(cur, fid)["asha"])
        cur.execute(
            "SELECT count(*) AS n FROM audit_logs WHERE fiduciary_id = %s AND audit_action = 'PURGE_STATUS_UPDATED'",
            (fid,),
        )
        assert cur.fetchone()["n"] == 1


def test_expired_hold_on_the_request_itself_does_not_block_completion(tx):
    """P8-02 edge: evaluating the hold BEFORE the UPDATE must not let a request
    whose own expired hold passed the CW-11 check block itself."""
    from dpdpcms_py.services.compliance import ComplianceService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        request_id = _seed_purge(
            cur, fid, "asha", "care", status="LEGAL_HOLD_APPLIED", hold_until=datetime.now(UTC) - timedelta(days=1)
        )
        out = ComplianceService().update_purge_status(_ctx(fid, {"id": request_id, "status": "PURGE_COMPLETED"}))
    assert out["status"] == "PURGE_COMPLETED"
    assert out["cms_copy_erased"] == {"consent_records_touched": 1}


# ── audit ledger: verifier, certificates, index ──────────────────────────────
def _log(fid, user, action):
    from dpdpcms_py import audit

    audit.log_event(user, fid, "APP", None, action, {"a": action}, purpose_id="care", source_ip="9.9.9.9")


def _first_ts(cur, fid):
    cur.execute("SELECT min(timestamp) AS ts FROM audit_logs WHERE fiduciary_id = %s", (fid,))
    return cur.fetchone()["ts"]


def test_chain_verifies_intact_and_detects_tampering_on_real_rows(tx):
    """P6-01 / SEC-10: the hash-chain verifier must pass on an intact ledger and
    flag a tampered row when both are real rows. The tamper is rolled back
    with the test's transaction (P8-06), so the shared ledger stays intact."""
    from dpdpcms_py import audit

    with tx.cursor() as cur:
        fid, _pol = _seed_tenant(cur)
        for i in range(3):
            _log(fid, "asha", f"TEST_ACTION_{i}")
        since = _first_ts(cur, fid)

        result = audit.verify_chain(limit=100, fiduciary_id=fid, since=since)
        assert result["intact"] is True
        assert result["rows_checked"] == 3
        assert result["coverage_complete"] is True

        cur.execute("ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_no_update_delete")
        cur.execute(
            "UPDATE audit_logs SET context_details = 'tampered'"
            " WHERE id = (SELECT id FROM audit_logs WHERE fiduciary_id = %s ORDER BY timestamp DESC, id DESC LIMIT 1)",
            (fid,),
        )
        cur.execute("ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_no_update_delete")
        broken = audit.verify_chain(limit=100, fiduciary_id=fid, since=since)
    assert broken["intact"] is False, "tampering must be detected"
    assert any(b["reason"] == "CONTENT_MISMATCH" for b in broken["broken"])


def test_another_tenants_break_fails_a_scoped_verification(tx):
    """SEC-10: the chain is global. A break in tenant B's rows must make tenant
    A's scoped verification fail too — reported as a count, without B's ids."""
    from dpdpcms_py import audit

    with tx.cursor() as cur:
        fid_a, _ = _seed_tenant(cur)
        fid_b, _ = _seed_tenant(cur)
        _log(fid_a, "asha", "A1")
        _log(fid_b, "bina", "B1")
        _log(fid_a, "asha", "A2")
        since = _first_ts(cur, fid_a)
        assert audit.verify_chain(limit=100, fiduciary_id=fid_a, since=since)["intact"] is True

        cur.execute("ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_no_update_delete")
        cur.execute("UPDATE audit_logs SET context_details = 'tampered' WHERE fiduciary_id = %s", (fid_b,))
        cur.execute("ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_no_update_delete")
        cur.execute("SELECT id FROM audit_logs WHERE fiduciary_id = %s", (fid_b,))
        b_ids = {str(r["id"]) for r in cur.fetchall()}
        result = audit.verify_chain(limit=100, fiduciary_id=fid_a, since=since)
    assert result["intact"] is False
    assert result["broken_count"] == 0
    assert result["foreign_broken_count"] >= 1
    assert not b_ids & {b["id"] for b in result["broken"]}


def test_partial_window_is_reported_incomplete_and_certificates_anchor_on_their_trail(tx, monkeypatch):
    """P7-02 / P8-04: a window holding only part of a tenant's rows used to
    certify. It now reports coverage_complete False with the real counts, and
    certificate generation anchors the walk on its own oldest trail entry."""
    from dpdpcms_py import audit
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services import governance

    with tx.cursor() as cur:
        fid_a, _ = _seed_tenant(cur)
        fid_b, _ = _seed_tenant(cur)
        _log(fid_a, "asha", "A1")
        _log(fid_a, "asha", "A2")
        for i in range(3):
            _log(fid_b, "bina", f"B{i}")
        _log(fid_a, "asha", "A3")

        window = audit.verify_chain(limit=4, fiduciary_id=fid_a)
        assert window["rows_checked"] == 1
        assert window["rows_in_scope_total"] == 3
        assert window["rows_unexamined"] == 2
        assert window["truncated"] is True
        assert window["coverage_complete"] is False

        ctx = _ctx(fid_a, {"fiduciary_id": fid_a, "subject_principal_id": "asha", "case_ref_id": "c1"})
        # An anchored walk too small to reach the trail's oldest row is refused.
        monkeypatch.setattr(governance, "ANCHORED_CHAIN_CHECK_ROWS", 2)
        with pytest.raises(ApiError) as exc:
            governance.LegalService().generate_certificate(ctx)
        assert exc.value.status == 409 and "examined" in exc.value.message

        monkeypatch.setattr(governance, "ANCHORED_CHAIN_CHECK_ROWS", 1_000_000)
        cert_id = governance.LegalService().generate_certificate(ctx)["certificate_id"]
        verify_ctx = _ctx(fid_a, {"id": cert_id})
        assert governance.LegalService().verify_certificate(verify_ctx)["valid"] is True

        # SEC-10 completeness: a trail with one of the principal's events
        # dropped (and re-signed, so the signature still checks) is rejected
        # against the principal's actual ledger.
        cur.execute("SELECT certificate_data FROM evidence_certificates WHERE id = %s", (cert_id,))
        data = cur.fetchone()["certificate_data"]
        assert len(data["evidence_trail"]) == 3
        data["evidence_trail"] = [data["evidence_trail"][0], data["evidence_trail"][2]]
        data["signature"] = audit.certificate_signature(data)
        cur.execute(
            "UPDATE evidence_certificates SET certificate_data = %s WHERE id = %s", (real_db.as_jsonb(data), cert_id)
        )
        result = governance.LegalService().verify_certificate(verify_ctx)
    assert result["valid"] is False
    assert "missing or extra" in result["reason"]


def test_chain_order_is_index_backed_and_full_walk_runs_in_the_worker(tx):
    """P6-12: the verifier's ORDER BY timestamp DESC, id DESC has a supporting
    index, and the full-ledger walk is a once-a-day worker sweep whose verdict
    the on-demand endpoint reports."""
    from dpdpcms_py import audit

    with tx.cursor() as cur:
        cur.execute("SET LOCAL enable_seqscan = off")
        cur.execute("EXPLAIN SELECT id FROM audit_logs ORDER BY timestamp DESC, id DESC LIMIT 100")
        plan = " ".join(r["QUERY PLAN"] for r in cur.fetchall())
        assert "idx_audit_logs_chain_order" in plan
        assert "Sort" not in plan.split("Limit")[1] if "Limit" in plan else True

        cur.execute("DELETE FROM job_schedule_state WHERE job_name = 'audit_chain_verification'")
        first = audit.record_chain_verification(limit=1_000)
        assert "intact" in first
        assert audit.record_chain_verification(limit=1_000) == {"skipped": True}
        latest = audit.latest_chain_verification()
    assert latest is not None and latest["rows_checked"] == first["rows_checked"]


# ── Rule 6(1)(e) floor triggers (db/23, db/24) ────────────────────────────────
def _raises(conn, sql, params=()):
    with pytest.raises(psycopg.errors.RaiseException) as exc:
        with conn.transaction(), conn.cursor() as cur:
            cur.execute(sql, params)
    return str(exc.value)


def test_delivery_floor_blocks_delete_truncate_and_in_place_rewrites(tx):
    """P7-04: DELETE and TRUNCATE were gated, UPDATE was not — the recipient
    could be blanked in place. Inside the floor, the personal-data columns may
    now change only to the erasure pseudonym; bookkeeping updates still work."""
    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type)"
            " VALUES ('PRINCIPAL', 'asha', %s, 'CONSENT_RECORDED') RETURNING id",
            (fid,),
        )
        nid = cur.fetchone()["id"]
        cur.execute(
            "INSERT INTO notification_deliveries (notification_id, channel, recipient) VALUES (%s, 'SMS', '+911234') RETURNING id",
            (nid,),
        )
        did = cur.fetchone()["id"]
        cur.execute(
            "INSERT INTO webhook_deliveries (fiduciary_id, category, event_type, payload)"
            " VALUES (%s, 'NOTIFICATION', 'CONSENT_GIVEN', %s) RETURNING id",
            (fid, real_db.as_jsonb({"user_id": "asha", "purpose": "care"})),
        )
        wid = cur.fetchone()["id"]

    assert "one-year floor" in _raises(tx, "DELETE FROM notification_deliveries WHERE id = %s", (did,))
    assert "TRUNCATE" in _raises(tx, "TRUNCATE notification_deliveries")
    assert "TRUNCATE" in _raises(tx, "TRUNCATE webhook_deliveries")
    assert "recipient" in _raises(tx, "UPDATE notification_deliveries SET recipient = '' WHERE id = %s", (did,))
    assert "immutable" in _raises(tx, "UPDATE notification_deliveries SET channel = 'EMAIL' WHERE id = %s", (did,))
    assert "payload" in _raises(tx, "UPDATE webhook_deliveries SET payload = payload - 'purpose' WHERE id = %s", (wid,))
    # P8-03: deleting the parent notification names the real cause.
    assert "notification" in _raises(tx, "DELETE FROM notifications WHERE id = %s", (nid,))

    with tx.cursor() as cur:
        cur.execute("UPDATE notification_deliveries SET status = 'SENT', attempt_count = 1 WHERE id = %s", (did,))
        cur.execute("UPDATE notification_deliveries SET recipient = 'erased:abc' WHERE id = %s", (did,))
        cur.execute(
            "UPDATE webhook_deliveries SET payload = jsonb_set(payload, '{user_id}', '\"erased:abc\"') WHERE id = %s",
            (wid,),
        )
        cur.execute("SELECT recipient, status FROM notification_deliveries WHERE id = %s", (did,))
        row = cur.fetchone()
    assert row == {"recipient": "erased:abc", "status": "SENT"}


def test_floor_migration_is_idempotent_across_its_previous_version(tx):
    """P8-03: a database that applied the EARLIER db/23 (old function and
    trigger names) must end with exactly the current triggers after db/23 and
    db/24 are re-applied — no double-firing old trigger, no orphaned function."""
    old_version = """
        CREATE OR REPLACE FUNCTION enforce_notification_delivery_floor() RETURNS trigger AS $$
        BEGIN RETURN OLD; END; $$ LANGUAGE plpgsql;
        DROP TRIGGER IF EXISTS notification_deliveries_floor ON notification_deliveries;
        CREATE TRIGGER notification_deliveries_floor BEFORE DELETE ON notification_deliveries
            FOR EACH ROW EXECUTE FUNCTION enforce_notification_delivery_floor();
    """
    with tx.cursor() as cur:
        cur.execute(old_version)
        for name in ("23_notification_delivery_floor.sql", "24_p8_remediation.sql", "24_p8_remediation.sql"):
            # CONCURRENTLY cannot run inside the test's transaction; the index
            # already exists, so the plain form is equivalent here.
            sql = (REPO / "db" / name).read_text(encoding="utf-8")
            cur.execute(sql.replace("CREATE INDEX CONCURRENTLY", "CREATE INDEX"))
        cur.execute(
            "SELECT tgname FROM pg_trigger WHERE tgrelid = 'notification_deliveries'::regclass AND NOT tgisinternal"
            " ORDER BY tgname"
        )
        names = [r["tgname"] for r in cur.fetchall()]
        cur.execute("SELECT count(*) AS n FROM pg_proc WHERE proname = 'enforce_notification_delivery_floor'")
        orphaned = cur.fetchone()["n"]
    assert names == [
        "trg_notification_deliveries_floor",
        "trg_notification_deliveries_no_truncate",
        "trg_notification_deliveries_update_floor",
    ]
    assert orphaned == 0


# ── P7-05 grievance assignment ───────────────────────────────────────────────
def test_console_assignment_matches_auto_route_and_notifies_the_assignee(tx):
    """P7-05: assign_grievance used to notify only the principal and force
    IN_PROGRESS. It now leaves the status as the auto-route does and sends the
    assignee a DPO-facing notice carrying the grievance reference."""
    from dpdpcms_py.delivery import render_message
    from dpdpcms_py.services.compliance import GrievanceService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO operators (name, email_plaintext, role, fiduciary_id, email_enc, email_hmac)"
            " VALUES ('Dee', 'dee@example.org', 'DPO', %s, 'x', %s) RETURNING id",
            (fid, f"h-{fid}"),
        )
        op = str(cur.fetchone()["id"])
        cur.execute(
            "INSERT INTO grievances (user_id, fiduciary_id, type, subject, description, reference_number)"
            " VALUES ('asha', %s, 'CONSENT_COMPLAINT', 's', 'd', 'GRV-2026-ABC123') RETURNING id",
            (fid,),
        )
        gid = str(cur.fetchone()["id"])

        out = GrievanceService().assign_grievance(_ctx(fid, {"grievance_id": gid, "operator_id": op}))
        assert out == {"success": True, "status": "NEW"}

        cur.execute("SELECT status, assigned_dpo_user_id FROM grievances WHERE id = %s", (gid,))
        row = cur.fetchone()
        assert row["status"] == "NEW" and str(row["assigned_dpo_user_id"]) == op
        cur.execute(
            "SELECT recipient_type, recipient_id, notification_type, context FROM notifications"
            " WHERE fiduciary_id = %s ORDER BY recipient_type",
            (fid,),
        )
        notes = cur.fetchall()
        _subject, body = render_message(fid, "GRIEVANCE_ROUTED", "DPO", notes[0]["context"])
    assert [(n["recipient_type"], n["notification_type"]) for n in notes] == [
        ("DPO", "GRIEVANCE_ROUTED"),
        ("PRINCIPAL", "GRIEVANCE_ASSIGNED"),
    ]
    assert notes[0]["recipient_id"] == op
    assert "GRV-2026-ABC123" in body and "CONSENT_COMPLAINT" in body


# ── P8-07 batched retention lookup ───────────────────────────────────────────
def test_batched_retention_lookup_matches_the_single_purpose_lookup(tx):
    from dpdpcms_py.services.retention import retention_for, retention_for_purposes

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO retention_policies (fiduciary_id, name, applicable_purposes, retention_duration_value,"
            " retention_duration_unit) VALUES (%s, 'care', %s, 2, 'YEARS')",
            (fid, real_db.as_jsonb(["care"])),
        )
        cur.execute(
            "INSERT INTO ropa_entries (fiduciary_id, activity_name, purpose, legal_basis, retention_period_days,"
            " retention_start_event, status, source_purpose_id) VALUES (%s, 'r', 'r', 'consent', 400, 'COLLECTION', 'active', 'research')",
            (fid,),
        )
        batch = retention_for_purposes(fid, ["care", "research", "none"])
        singles = {pid: retention_for(fid, pid) for pid in ("care", "research", "none")}
    assert batch == singles == {"care": (730, "CESSATION"), "research": (400, "COLLECTION"), "none": (None, None)}


# ── P7-03 nomination status precedence ───────────────────────────────────────
def test_nomination_is_reported_with_the_status_it_was_selected_by(tx):
    from dpdpcms_py.services.rights import RightsService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO nominations (fiduciary_id, nominating_principal_id, nominated_principal_id, valid_from, valid_until)"
            " VALUES (%s, 'asha', 'ravi', NOW() + INTERVAL '10 days', NOW() - INTERVAL '1 day')",
            (fid,),
        )
        rows = RightsService().list_nominations(_ctx(fid, {"status": "PENDING"}))
    assert len(rows) == 1
    assert rows[0]["effective_status"] == "PENDING"


# ── PL-03 end to end: closure with a retention period ─────────────────────────
def test_closure_with_retention_defers_then_sweep_raises_and_completes_the_purge(tx):
    """PL-03: closing a purpose that a retention period governs raises no purge
    at closure; once the period has run from closure, the sweep raises one per
    principal carrying the closure's DE_IDENTIFY action, and confirming it
    de-identifies that principal's entry (the P8-01 path, end to end)."""
    from dpdpcms_py import jobs
    from dpdpcms_py.services.compliance import ComplianceService
    from dpdpcms_py.services.lifecycle import close_purpose_exec

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("care", "research"))
        _seed_consent(cur, fid, pol, "asha", purposes=("care", "research"))
        cur.execute("INSERT INTO purpose_lifecycle (fiduciary_id, purpose_id) VALUES (%s, 'research')", (fid,))
        cur.execute(
            "INSERT INTO retention_policies (fiduciary_id, name, applicable_purposes, retention_duration_value,"
            " retention_duration_unit, action_at_expiry) VALUES (%s, 'research', %s, 1, 'DAYS', 'DE_IDENTIFY')",
            (fid, real_db.as_jsonb(["research"])),
        )

        closed = close_purpose_exec(fid, "research", reason="study ended", deidentification_action="DE_IDENTIFY")
        assert closed["purge_requests_created"] == 0 and closed["retention_deferred_days"] == 1

        cur.execute(
            "UPDATE purpose_lifecycle SET closed_at = NOW() - INTERVAL '2 days' WHERE fiduciary_id = %s", (fid,)
        )
        jobs.run_retention_sweep()
        cur.execute(
            "SELECT id, user_id, action, trigger_event FROM purge_requests WHERE fiduciary_id = %s AND purpose_id = 'research'",
            (fid,),
        )
        purges = cur.fetchall()
        assert [(p["user_id"], p["action"], p["trigger_event"]) for p in purges] == [
            ("asha", "DE_IDENTIFY", "RetentionPolicyExpiry")
        ]

        out = ComplianceService().update_purge_status(
            _ctx(fid, {"id": str(purges[0]["id"]), "status": "PURGE_COMPLETED"})
        )
        assert out["cms_copy_erased"] == {"consent_records_touched": 1}
        entries = _consents(cur, fid)["asha"]
    assert [p["status"] for p in entries if p.get("status") == "de_identified"] == ["de_identified"]
    assert any(p.get("data_point_id") == "care" for p in entries)


# ── SA-13 notification_deliveries retention ──────────────────────────────────
def test_notification_delivery_retention_prunes_only_terminal_rows_past_the_floor(tx):
    from dpdpcms_py import jobs

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type)"
            " VALUES ('PRINCIPAL', 'asha', %s, 'CONSENT_RECORDED') RETURNING id",
            (fid,),
        )
        nid = cur.fetchone()["id"]
        for status, age in (("SENT", 400), ("PENDING", 400), ("SENT", 30)):
            cur.execute(
                "INSERT INTO notification_deliveries (notification_id, channel, recipient, status, created_at)"
                " VALUES (%s, 'SMS', '+91', %s, NOW() - make_interval(days => %s))",
                (nid, status, age),
            )
        # A requested 30-day retention is clamped up to the one-year floor.
        out = jobs.prune_old_notification_deliveries(days=30)
        cur.execute(
            "SELECT status, (created_at < NOW() - INTERVAL '365 days') AS old FROM notification_deliveries"
            " WHERE notification_id = %s ORDER BY status",
            (nid,),
        )
        left = [(r["status"], r["old"]) for r in cur.fetchall()]
    assert out["retention_days"] == 365 and out["floor_enforced"] is True
    assert left == [("PENDING", True), ("SENT", False)]


# ── GR-07 category routing to a department ───────────────────────────────────
def _seed_operator(cur, fid, role, name):
    cur.execute(
        "INSERT INTO operators (name, email_plaintext, role, fiduciary_id, email_enc, email_hmac)"
        " VALUES (%s, %s, %s, %s, 'x', %s) RETURNING id",
        (name, f"{name}@example.org", role, fid, f"h-{name}-{fid}"),
    )
    return str(cur.fetchone()["id"])


def test_grievance_category_routes_to_its_department_else_the_dpo(tx):
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.compliance import GrievanceService

    service = GrievanceService()
    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        dpo = _seed_operator(cur, fid, "DPO", "dee")
        records = _seed_operator(cur, fid, "OPERATOR", "rek")
        other_fid, _ = _seed_tenant(cur)
        outsider = _seed_operator(cur, other_fid, "OPERATOR", "out")

        with pytest.raises(ApiError) as exc:
            service.set_grievance_routing(
                _ctx(fid, {"grievance_type": "CORRECTION_REQUEST", "department": "Records", "operator_id": outsider})
            )
        assert exc.value.status == 404, "an officer from another tenant must not be routable"
        service.set_grievance_routing(
            _ctx(fid, {"grievance_type": "correction_request", "department": "Medical Records", "operator_id": records})
        )

        def submit(kind):
            ctx = _ctx(fid, {"user_id": "asha", "type": kind, "subject": "s", "description": "d"})
            gid = service.submit_grievance(ctx)["grievance_id"]
            cur.execute("SELECT status, assigned_dpo_user_id, department FROM grievances WHERE id = %s", (gid,))
            row = cur.fetchone()
            return row["status"], str(row["assigned_dpo_user_id"]), row["department"]

        routed = submit("CORRECTION_REQUEST")
        fallback = submit("CONSENT_COMPLAINT")
        listing = {r["grievance_type"]: r for r in service.list_grievance_routing(_ctx(fid, {}))}

        service.set_grievance_routing(_ctx(fid, {"grievance_type": "CORRECTION_REQUEST", "remove": True}))
        after_removal = submit("CORRECTION_REQUEST")
    assert routed == ("NEW", records, "Medical Records")
    assert fallback == ("NEW", dpo, "DPO")
    assert listing["CORRECTION_REQUEST"]["department"] == "Medical Records"
    assert listing["CONSENT_COMPLAINT"]["department"] == "DPO"
    assert after_removal == ("NEW", dpo, "DPO")


# ── NT-03 delivery in the principal's language ───────────────────────────────
def test_principal_notification_renders_in_the_language_they_chose(tx):
    from dpdpcms_py.delivery import principal_language, render_message

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        cur.execute("UPDATE consent_records SET language_selected = 'hi' WHERE fiduciary_id = %s", (fid,))
        cur.execute(
            "INSERT INTO notification_message_templates (fiduciary_id, notification_type, messages) VALUES (%s, %s, %s)",
            (fid, "CONSENT_RECORDED", real_db.as_jsonb({"en": "Recorded.", "hi": "आपकी सहमति दर्ज की गई।"})),
        )
        language = principal_language(fid, "asha")
        _s, hindi = render_message(fid, "CONSENT_RECORDED", "PRINCIPAL", language=language)
        _s, fallback = render_message(fid, "CONSENT_RECORDED", "PRINCIPAL", language="ta")
    assert language == "hi"
    assert hindi == "आपकी सहमति दर्ज की गई।"
    assert fallback == "Recorded."


# ── review follow-ups ─────────────────────────────────────────────────────────
def test_backfill_never_redispatches_a_notification_whose_deliveries_were_pruned(tx):
    """SA-13: pruning old delivery rows must not make the backfill re-send them."""
    from dpdpcms_py import delivery

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type, created_at)"
            " VALUES ('PRINCIPAL', 'asha', %s, 'CONSENT_RECORDED', NOW() - INTERVAL '400 days') RETURNING id",
            (fid,),
        )
        old = cur.fetchone()["id"]
        delivery._backfill_deliveries(10_000)
        cur.execute("SELECT count(*) AS n FROM notification_deliveries WHERE notification_id = %s", (old,))
        assert cur.fetchone()["n"] == 0


def test_erase_keeps_consent_entries_that_carry_no_purpose_id(tx):
    from dpdpcms_py.services.compliance import deidentify_purpose_cms_copy

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        cur.execute(
            "UPDATE consent_records SET data_point_consents = data_point_consents || %s WHERE fiduciary_id = %s",
            (real_db.as_jsonb([{"note": "no id"}]), fid),
        )
        deidentify_purpose_cms_copy(fid, "asha", "care", action="ERASE")
        assert _consents(cur, fid)["asha"] == [{"note": "no id"}]


def test_routing_rejects_an_officer_who_cannot_act_on_grievances(tx):
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services import roles
    from dpdpcms_py.services.compliance import GrievanceService

    assert roles.required_permission("grievance", "set_grievance_routing") == "operator:write"
    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        auditor = _seed_operator(cur, fid, "AUDITOR", "aud")
        with pytest.raises(ApiError) as exc:
            GrievanceService().set_grievance_routing(
                _ctx(fid, {"grievance_type": "GENERAL_COMPLAINT", "department": "Audit", "operator_id": auditor})
            )
    assert exc.value.status == 400 and "grievance:write" in exc.value.message


def test_certificate_omitting_earlier_events_is_rejected(tx):
    """A trail that does not declare truncation claims the whole history; an
    earlier event of the principal it leaves out invalidates it."""
    from dpdpcms_py import audit
    from dpdpcms_py.services import governance

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        for i in range(3):
            _log(fid, "asha", f"E{i}")
        ctx = _ctx(fid, {"fiduciary_id": fid, "subject_principal_id": "asha"})
        cert_id = governance.LegalService().generate_certificate(ctx)["certificate_id"]
        cur.execute("SELECT certificate_data FROM evidence_certificates WHERE id = %s", (cert_id,))
        data = cur.fetchone()["certificate_data"]
        assert data["trail_truncated"] is False
        data["evidence_trail"] = data["evidence_trail"][:2]  # drop the OLDEST event
        data["signature"] = audit.certificate_signature(data)
        cur.execute(
            "UPDATE evidence_certificates SET certificate_data = %s WHERE id = %s", (real_db.as_jsonb(data), cert_id)
        )
        result = governance.LegalService().verify_certificate(_ctx(fid, {"id": cert_id}))
    assert result["valid"] is False and "earlier events" in result["reason"]


# ── legal-hold race: check and de-identification are atomic per principal ─────
def test_hold_written_concurrently_is_honoured_not_raced():
    """A hold being written by an erasure request (holding the per-principal
    lock, not yet committed) makes a concurrent purge confirmation WAIT, then
    see the hold and refuse — instead of passing the check in the gap and
    de-identifying held data. Real separate connections; seeded rows are
    removed afterwards."""
    import threading
    import time

    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.compliance import ComplianceService, lock_principal_purges

    with psycopg.connect(settings.db_dsn, row_factory=dict_row) as setup:
        with setup.cursor() as cur:
            fid, pol = _seed_tenant(cur)
            _seed_consent(cur, fid, pol, "asha")
            request_id = _seed_purge(cur, fid, "asha", "care", action="DE_IDENTIFY")
        setup.commit()
    outcome: dict = {}

    def confirm():
        try:
            outcome["result"] = ComplianceService().update_purge_status(
                _ctx(fid, {"id": request_id, "status": "PURGE_COMPLETED"})
            )
        except ApiError as exc:
            outcome["error"] = exc.status
        except Exception as exc:  # noqa: BLE001 - surface it in the assertion, not a silent thread
            outcome["unexpected"] = repr(exc)

    worker = None
    try:
        with psycopg.connect(settings.db_dsn, row_factory=dict_row) as writer:
            with writer.cursor() as cur:
                lock_principal_purges(cur, fid, "asha")  # the erasure path, mid-transaction
                _seed_purge(
                    cur,
                    fid,
                    "asha",
                    "ALL",
                    status="LEGAL_HOLD_APPLIED",
                    hold_until=datetime.now(UTC) + timedelta(days=30),
                    trigger="ErasureRequest",
                )
                worker = threading.Thread(target=confirm)
                worker.start()
                time.sleep(1.0)
                assert worker.is_alive(), "the confirmation must wait for the in-flight hold"
            writer.commit()
        worker.join(timeout=30)
        assert outcome == {"error": 409}
        with psycopg.connect(settings.db_dsn, row_factory=dict_row) as check, check.cursor() as cur:
            cur.execute("SELECT status FROM purge_requests WHERE id = %s", (request_id,))
            assert cur.fetchone()["status"] == "PENDING"
            assert _consents(cur, fid)["asha"][0]["data_point_id"] == "care", "held data was de-identified"
    finally:
        # Never clean up under a still-running confirmation.
        if worker is not None:
            worker.join(timeout=30)
        with psycopg.connect(settings.db_dsn) as cleanup, cleanup.cursor() as cur:
            cur.execute("DELETE FROM purge_requests WHERE fiduciary_id = %s", (fid,))
            cur.execute("DELETE FROM consent_records WHERE fiduciary_id = %s", (fid,))
            cur.execute("DELETE FROM consent_policies WHERE fiduciary_id = %s", (fid,))
            cur.execute("DELETE FROM fiduciaries WHERE id = %s", (fid,))


def test_assign_grievance_rejects_an_officer_who_cannot_act(tx):
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.compliance import GrievanceService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        auditor = _seed_operator(cur, fid, "AUDITOR", "aud2")
        cur.execute(
            "INSERT INTO grievances (user_id, fiduciary_id, type, subject, description)"
            " VALUES ('asha', %s, 'GENERAL_COMPLAINT', 's', 'd') RETURNING id",
            (fid,),
        )
        gid = str(cur.fetchone()["id"])
        with pytest.raises(ApiError) as exc:
            GrievanceService().assign_grievance(_ctx(fid, {"grievance_id": gid, "operator_id": auditor}))
        cur.execute("SELECT assigned_dpo_user_id FROM grievances WHERE id = %s", (gid,))
        assigned = cur.fetchone()["assigned_dpo_user_id"]
    assert exc.value.status == 400 and assigned is None
