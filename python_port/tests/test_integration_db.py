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
import re
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


# SQL literals for "asha" stored as db/34 stores it, for tests that write a
# consent row inline (the tx fixture sets app.enc_key on the connection).
_ASHA_ENC = "encode(pgp_sym_encrypt('asha', current_setting('app.enc_key')), 'base64')"
_ASHA_HMAC = "encode(hmac('asha', current_setting('app.enc_key'), 'sha256'), 'hex')"


def _pid(cur, value):
    """(enc, hmac) of a principal id, exactly as the services store it (db/34)."""
    from dpdpcms_py import pii

    cur.execute(
        f"SELECT {pii.ENC_SQL} AS enc, {pii.HMAC_SQL} AS hmac", (*pii.enc_params(value), *pii.hmac_params(value))
    )
    row = cur.fetchone()
    return row["enc"], row["hmac"]


def _seed_consent(cur, fid, pol, user, purposes=("care",), ip="1.2.3.4", user_agent=None, language="en", granted=True):
    cur.execute(
        "INSERT INTO consent_records (id, user_id_enc, user_id_hmac, fiduciary_id, policy_id, policy_version, "
        " timestamp, jurisdiction, language_selected, data_point_consents, is_active_consent, "
        " consent_status_general, consent_mechanism, ip_address, user_agent, created_at, last_updated_at) "
        "VALUES (uuid_generate_v4(), %s, %s, %s, %s, 'v1', NOW(), 'IN', %s, %s, TRUE, "
        " 'CONSENT_GIVEN', 'WEB', %s, %s, NOW(), NOW())",
        (
            *_pid(cur, user),
            fid,
            pol,
            language,
            real_db.as_jsonb(
                [{"data_point_id": p, "purpose_agreed_to": p.title(), "consent_granted": granted} for p in purposes]
            ),
            ip,
            user_agent,
        ),
    )


def _consents(cur, fid):
    from dpdpcms_py import pii

    cur.execute(
        f"SELECT {pii.dec_sql('user_id_enc')} AS user_id, data_point_consents FROM consent_records"
        " WHERE fiduciary_id = %s ORDER BY 1",
        (*real_db.bind_key(), fid),
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
    from dpdpcms_py import pii
    from dpdpcms_py.services.compliance import erase_cms_copy

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha", ip="9.9.9.9", user_agent="curl/8")

        erase_cms_copy(fid, "asha")

        cur.execute(
            "SELECT ip_address, user_agent FROM consent_records WHERE fiduciary_id = %s"
            f" AND {pii.dec_sql('user_id_enc')} LIKE 'erased:%%'",
            (fid, *real_db.bind_key()),
        )
        row = cur.fetchone()
    assert row is not None
    assert str(row["ip_address"]) == "0.0.0.0"
    assert row["user_agent"] is None


# ── P8-02: purge status vs. the legal hold ───────────────────────────────────
def _seed_purge(cur, fid, user, purpose, status="PENDING", action="ERASE", hold_until=None, trigger="PurposeClosure"):
    cur.execute(
        "INSERT INTO purge_requests (user_id_enc, user_id_hmac, fiduciary_id, purpose_id, trigger_event, status,"
        " action, hold_until) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
        (*_pid(cur, user), fid, purpose, trigger, status, action, hold_until),
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
        ctx = _confirm_ctx(fid, request_id)

        with pytest.raises(ApiError) as exc:
            ComplianceService().confirm_purge_status(ctx)
        assert exc.value.status == 409

        cur.execute("SELECT status, completed_at FROM purge_requests WHERE id = %s", (request_id,))
        row = cur.fetchone()
        assert row["status"] == "PENDING", "P8-02: a refused request must not be recorded complete"
        assert row["completed_at"] is None
        assert any(p["data_point_id"] == "research" for p in _consents(cur, fid)["asha"])

        # Lift the hold: the same confirmation now completes end to end.
        cur.execute("UPDATE purge_requests SET status = 'COMPLETED' WHERE id = %s", (hold_id,))
        out = ComplianceService().confirm_purge_status(ctx)
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
        out = ComplianceService().confirm_purge_status(_confirm_ctx(fid, request_id))
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
        # db/32: audit_logs is partitioned, so the plan is a Merge Append over
        # each partition's copy of the index; ANALYZE (rolled back with the
        # test) so the planner costs the real, not the default, row counts.
        cur.execute("ANALYZE audit_logs")
        cur.execute("EXPLAIN SELECT id FROM audit_logs ORDER BY timestamp DESC, id DESC LIMIT 100")
        plan = " ".join(r["QUERY PLAN"] for r in cur.fetchall())
        cur.execute(
            "SELECT inhrelid::regclass::text AS name FROM pg_inherits"
            " WHERE inhparent = 'public.idx_audit_logs_chain_order'::regclass"
        )
        chain_indexes = {"idx_audit_logs_chain_order", *(r["name"] for r in cur.fetchall())}
        assert any(name in plan for name in chain_indexes)
        assert not re.search(r"-> +Sort +\(", plan), plan

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
            "INSERT INTO notifications (recipient_type, recipient_id_enc, recipient_id_hmac, fiduciary_id,"
            " notification_type) VALUES ('PRINCIPAL', %s, %s, %s, 'CONSENT_RECORDED') RETURNING id",
            (*_pid(cur, "asha"), fid),
        )
        nid = cur.fetchone()["id"]
        cur.execute(
            "INSERT INTO notification_deliveries (notification_id, channel, recipient_enc, recipient_hmac)"
            " VALUES (%s, 'SMS', %s, %s) RETURNING id",
            (nid, *_pid(cur, "+911234")),
        )
        did = cur.fetchone()["id"]
        erased_enc, erased_hmac = _pid(cur, "erased:abc")
        cur.execute(
            "INSERT INTO webhook_deliveries (fiduciary_id, category, event_type, payload)"
            " VALUES (%s, 'NOTIFICATION', 'CONSENT_GIVEN', %s) RETURNING id",
            (fid, real_db.as_jsonb({"user_id": "asha", "purpose": "care"})),
        )
        wid = cur.fetchone()["id"]

    assert "one-year floor" in _raises(tx, "DELETE FROM notification_deliveries WHERE id = %s", (did,))
    assert "TRUNCATE" in _raises(tx, "TRUNCATE notification_deliveries")
    assert "TRUNCATE" in _raises(tx, "TRUNCATE webhook_deliveries")
    assert "recipient" in _raises(tx, "UPDATE notification_deliveries SET recipient_enc = '' WHERE id = %s", (did,))
    assert "immutable" in _raises(tx, "UPDATE notification_deliveries SET channel = 'EMAIL' WHERE id = %s", (did,))
    assert "payload" in _raises(tx, "UPDATE webhook_deliveries SET payload = payload - 'purpose' WHERE id = %s", (wid,))
    # P8-03: deleting the parent notification names the real cause.
    assert "notification" in _raises(tx, "DELETE FROM notifications WHERE id = %s", (nid,))

    with tx.cursor() as cur:
        cur.execute("UPDATE notification_deliveries SET status = 'SENT', attempt_count = 1 WHERE id = %s", (did,))
        cur.execute(
            "UPDATE notification_deliveries SET recipient_enc = %s, recipient_hmac = %s WHERE id = %s",
            (erased_enc, erased_hmac, did),
        )
        cur.execute(
            "UPDATE webhook_deliveries SET payload = jsonb_set(payload, '{user_id}', '\"erased:abc\"') WHERE id = %s",
            (wid,),
        )
        cur.execute("SELECT recipient_hmac, status FROM notification_deliveries WHERE id = %s", (did,))
        row = cur.fetchone()
    assert row == {"recipient_hmac": erased_hmac, "status": "SENT"}


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
            # already exists, so the plain form is equivalent here. psql
            # meta-commands (db/24's \gset / \if guard) are psql-only; drop them.
            sql = (REPO / "db" / name).read_text(encoding="utf-8")
            sql = "\n".join(
                line for line in sql.splitlines() if "\\gset" not in line and not line.lstrip().startswith("\\")
            )
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
            "INSERT INTO grievances (user_id_enc, user_id_hmac, fiduciary_id, type, subject, description,"
            f" reference_number) VALUES ({_ASHA_ENC}, {_ASHA_HMAC}, %s, 'CONSENT_COMPLAINT', 's', 'd', 'GRV-2026-ABC123') RETURNING id",
            (fid,),
        )
        gid = str(cur.fetchone()["id"])

        out = GrievanceService().assign_grievance(_ctx(fid, {"grievance_id": gid, "operator_id": op}))
        assert out == {"success": True, "status": "NEW"}

        cur.execute("SELECT status, assigned_dpo_user_id FROM grievances WHERE id = %s", (gid,))
        row = cur.fetchone()
        assert row["status"] == "NEW" and str(row["assigned_dpo_user_id"]) == op
        cur.execute(
            f"SELECT recipient_type, {real_db.decrypt_col('recipient_id_enc')} AS recipient_id, notification_type,"
            " context FROM notifications WHERE fiduciary_id = %s ORDER BY recipient_type",
            (*real_db.bind_key(), fid),
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
            "INSERT INTO nominations (fiduciary_id, nominating_principal_id_enc, nominating_principal_id_hmac,"
            " nominated_principal_id_enc, nominated_principal_id_hmac, valid_from, valid_until)"
            " VALUES (%s, %s, %s, %s, %s, NOW() + INTERVAL '10 days', NOW() - INTERVAL '1 day')",
            (fid, *_pid(cur, "asha"), *_pid(cur, "ravi")),
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
            f"SELECT id, {real_db.decrypt_col('user_id_enc')} AS user_id, action, trigger_event FROM purge_requests"
            " WHERE fiduciary_id = %s AND purpose_id = 'research'",
            (*real_db.bind_key(), fid),
        )
        purges = cur.fetchall()
        assert [(p["user_id"], p["action"], p["trigger_event"]) for p in purges] == [
            ("asha", "DE_IDENTIFY", "RetentionPolicyExpiry")
        ]

        out = ComplianceService().confirm_purge_status(_confirm_ctx(fid, str(purges[0]["id"])))
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
            "INSERT INTO notifications (recipient_type, recipient_id_enc, recipient_id_hmac, fiduciary_id,"
            f" notification_type) VALUES ('PRINCIPAL', {_ASHA_ENC}, {_ASHA_HMAC}, %s, 'CONSENT_RECORDED') RETURNING id",
            (fid,),
        )
        nid = cur.fetchone()["id"]
        for status, age in (("SENT", 400), ("PENDING", 400), ("SENT", 30)):
            cur.execute(
                "INSERT INTO notification_deliveries (notification_id, channel, recipient_enc, recipient_hmac, status,"
                " created_at) VALUES (%s, 'SMS', %s, %s, %s, NOW() - make_interval(days => %s))",
                (nid, *_pid(cur, "+91"), status, age),
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
        _seed_consent(cur, fid, pol, "asha", language="hi")
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
            "INSERT INTO notifications (recipient_type, recipient_id_enc, recipient_id_hmac, fiduciary_id,"
            f" notification_type, created_at) VALUES ('PRINCIPAL', {_ASHA_ENC}, {_ASHA_HMAC}, %s, 'CONSENT_RECORDED',"
            " NOW() - INTERVAL '400 days') RETURNING id",
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
        real_db.allow_consent_maintenance(cur)
        cur.execute(
            "UPDATE consent_records SET data_point_consents = data_point_consents || %s WHERE fiduciary_id = %s",
            (real_db.as_jsonb([{"note": "no id"}]), fid),
        )
        cur.execute("SELECT set_config('tsi.consent_maintenance', 'off', true)")
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
            outcome["result"] = ComplianceService().confirm_purge_status(_confirm_ctx(fid, request_id))
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
            # P9-05 residual (db/26): no application path may DELETE a consent
            # record, so test cleanup bypasses the triggers as the superuser.
            cur.execute("SET LOCAL session_replication_role = replica")
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
            "INSERT INTO grievances (user_id_enc, user_id_hmac, fiduciary_id, type, subject, description)"
            f" VALUES ({_ASHA_ENC}, {_ASHA_HMAC}, %s, 'GENERAL_COMPLAINT', 's', 'd') RETURNING id",
            (fid,),
        )
        gid = str(cur.fetchone()["id"])
        with pytest.raises(ApiError) as exc:
            GrievanceService().assign_grievance(_ctx(fid, {"grievance_id": gid, "operator_id": auditor}))
        cur.execute("SELECT assigned_dpo_user_id FROM grievances WHERE id = %s", (gid,))
        assigned = cur.fetchone()["assigned_dpo_user_id"]
    assert exc.value.status == 400 and assigned is None


# ── workbook v7 (P9) ─────────────────────────────────────────────────────────
def _close(cur, fid, purpose):
    cur.execute(
        "INSERT INTO purpose_lifecycle (fiduciary_id, purpose_id, state, closed_at) VALUES (%s, %s, 'CLOSED', NOW())",
        (fid, purpose),
    )


def test_closed_purpose_does_not_validate_under_another_case(tx):
    """P9-01: 'marketing' must not validate while 'MARKETING' is closed."""
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("marketing",))
        _seed_consent(cur, fid, pol, "asha", purposes=("marketing",))
        _close(cur, fid, "MARKETING")
    for spelling in ("MARKETING", "marketing", "Marketing"):
        out = ConsentService().validate_consent(_ctx(fid, {"user_id": "asha", "required_purpose_id": spelling}))
        assert out["valid"] is False and out["metadata"]["purpose_status"] == "PURPOSE_CLOSED", spelling


@pytest.mark.parametrize("status", ["DRAFT", "ARCHIVED"])
def test_consent_refused_against_an_unpublished_policy(tx, status):
    """P9-02: consent rests only on the ACTIVE, in-effect notice."""
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.consent import check_consent_alignment

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        cur.execute("UPDATE consent_policies SET status = %s WHERE fiduciary_id = %s", (status, fid))
    with pytest.raises(ApiError) as exc:
        check_consent_alignment(fid, pol, "v1", [{"data_point_id": "care", "consent_granted": True}])
    assert exc.value.status == 409


def test_consent_accepted_against_the_active_policy(tx):
    from dpdpcms_py.services.consent import check_consent_alignment

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
    assert check_consent_alignment(fid, pol, "v1", [{"data_point_id": "care", "consent_granted": True}]) == set()


def test_marking_read_by_id_is_audited(tx):
    """P9-03: the schema's own 'id' field must not 500 or skip the audit row."""
    from dpdpcms_py.services.governance import NotificationService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO notifications (recipient_type, recipient_id_enc, recipient_id_hmac, fiduciary_id,"
            f" notification_type) VALUES ('PRINCIPAL', {_ASHA_ENC}, {_ASHA_HMAC}, %s, 'CONSENT_RECORDED') RETURNING id",
            (fid,),
        )
        nid = str(cur.fetchone()["id"])
    assert NotificationService().mark_notification_read(_ctx(fid, {"id": nid})) == {"success": True}
    with tx.cursor() as cur:
        cur.execute(
            "SELECT service_id FROM audit_logs WHERE fiduciary_id = %s AND audit_action = 'NOTIFICATION_ACKNOWLEDGED'",
            (fid,),
        )
        rows = cur.fetchall()
    assert [str(r["service_id"]) for r in rows] == [nid]


def test_reopening_a_purpose_cancels_its_pending_purges(tx):
    """P9-04: purges raised by the closure are moot once the purpose reopens,
    and the time-bound clock restarts. P10-05: only for principals whose
    consent to the purpose is still active, and only purges this closure raised."""
    from dpdpcms_py.services.lifecycle import PurposeLifecycleService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        for user in ("asha", "ramesh", "sita", "gita", "old"):
            _seed_consent(cur, fid, pol, user)
        _seed_consent(cur, fid, pol, "withdrew", granted=False)
        cur.execute(
            "INSERT INTO purpose_lifecycle (fiduciary_id, purpose_id, state, opened_at, closed_at)"
            " VALUES (%s, 'care', 'CLOSED', NOW() - INTERVAL '400 days', NOW() - INTERVAL '1 hour')",
            (fid,),
        )
        for user, trigger, status, age in (
            ("asha", "PurposeClosed", "PENDING", "1 minute"),
            ("ramesh", "RetentionPolicyExpiry", "PENDING", "1 minute"),
            ("sita", "PurposeClosed", "PURGE_IN_PROGRESS", "1 minute"),
            ("gita", "ErasureRequest", "PENDING", "1 minute"),
            ("withdrew", "PurposeClosed", "PENDING", "1 minute"),
            ("old", "PurposeClosed", "PENDING", "2 days"),
        ):
            cur.execute(
                "INSERT INTO purge_requests (user_id_enc, user_id_hmac, fiduciary_id, purpose_id, trigger_event, status,"
                " initiated_at) VALUES (%s, %s, %s, 'Care', %s, %s, NOW() - %s::interval)",
                (*_pid(cur, user), fid, trigger, status, age),
            )
    out = PurposeLifecycleService().set_purpose_state(_ctx(fid, {"purpose_id": "CARE ", "state": "OPEN"}))
    assert out["purge_requests_cancelled"] == 2
    with tx.cursor() as cur:
        cur.execute(
            f"SELECT {real_db.decrypt_col('user_id_enc')} AS user_id, status, purpose_id FROM purge_requests"
            " WHERE fiduciary_id = %s",
            (*real_db.bind_key(), fid),
        )
        rows = cur.fetchall()
        statuses = {r["user_id"]: r["status"] for r in rows}
        cur.execute(
            "SELECT opened_at > NOW() - INTERVAL '1 minute' AS fresh FROM purpose_lifecycle WHERE fiduciary_id = %s",
            (fid,),
        )
        fresh = cur.fetchone()["fresh"]
    assert {r["purpose_id"] for r in rows} == {"care"}, "db/26 stores the canonical purpose id"
    assert statuses == {
        "asha": "CANCELLED",
        "ramesh": "CANCELLED",
        "sita": "PURGE_IN_PROGRESS",
        "gita": "PENDING",
        "withdrew": "PENDING",
        "old": "PENDING",
    }
    assert fresh is True


def test_consent_records_are_append_only_in_the_database(tx):
    """P9-05: raw UPDATE and DELETE fail; the retirement flip still works."""
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        for sql in (
            "UPDATE consent_records SET data_point_consents = '[]'::jsonb WHERE fiduciary_id = %s",
            "UPDATE consent_records SET is_active_consent = FALSE, policy_version = 'v9' WHERE fiduciary_id = %s",
            "DELETE FROM consent_records WHERE fiduciary_id = %s",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege), tx.transaction():
                cur.execute(sql, (fid,))
        cur.execute(
            "UPDATE consent_records SET is_active_consent = FALSE, last_updated_at = NOW() WHERE fiduciary_id = %s",
            (fid,),
        )
        assert cur.rowcount == 1
        # Once retired, a record cannot be flipped back on.
        with pytest.raises(psycopg.errors.InsufficientPrivilege), tx.transaction():
            cur.execute("UPDATE consent_records SET is_active_consent = TRUE WHERE fiduciary_id = %s", (fid,))


def test_principal_self_check_is_not_an_integrator_denial(tx):
    """P9-06: a principal checking their own status writes no validation,
    denial notice or audit row."""
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("care", "research"))
        _seed_consent(cur, fid, pol, "asha", purposes=("care",))
    ctx = _ctx(
        fid,
        {"user_id": "asha", "required_purpose_id": "research"},
        auth_via_principal_jwt=True,
        principal_user_id="asha",
    )
    out = ConsentService().validate_consent(ctx)
    assert out["valid"] is False
    with tx.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM consent_validations WHERE fiduciary_id = %s", (fid,))
        validations = cur.fetchone()["n"]
        cur.execute("SELECT COUNT(*) AS n FROM notifications WHERE fiduciary_id = %s", (fid,))
        notices = cur.fetchone()["n"]
    assert validations == 0 and notices == 0


def test_withdrawal_with_nothing_active_is_refused(tx):
    """P9-07: no active consent means nothing to withdraw — and no cascade."""
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    with pytest.raises(ApiError) as exc:
        ConsentService().withdraw_consent(_ctx(fid, {"user_id": "nobody", "purpose_ids": ["care"]}))
    assert exc.value.status == 404
    with tx.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM notifications WHERE fiduciary_id = %s", (fid,))
        assert cur.fetchone()["n"] == 0


def _audit_actions(cur, fid):
    cur.execute("SELECT audit_action, context_details FROM audit_logs WHERE fiduciary_id = %s", (fid,))
    return cur.fetchall()


def test_update_user_applies_role_and_status_and_keeps_the_name(tx):
    """SA-04: role and status are applied; an omitted username is not nulled."""
    from dpdpcms_py.services.admin import OperatorService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        op = _seed_operator(cur, fid, "OPERATOR", "op1")
    OperatorService().update_user(_ctx(fid, {"user_id": op, "role": "AUDITOR", "status": "INACTIVE"}))
    with tx.cursor() as cur:
        cur.execute("SELECT name, role, status, tokens_valid_after FROM operators WHERE id = %s", (op,))
        row = cur.fetchone()
    assert (row["name"], row["role"], row["status"]) == ("op1", "AUDITOR", "INACTIVE")
    assert row["tokens_valid_after"] is not None


def test_dpo_cannot_assign_a_role_other_than_operator(tx):
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.admin import OperatorService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO operators (name, email_plaintext, role, fiduciary_id, email_enc, email_hmac)"
            f" VALUES ('dpo', 'dpo@example.org', 'DPO', %s, 'x', {real_db.hmac_expr()})",
            (fid, *real_db.bind_hmac("dpo@example.org")),
        )
        op = _seed_operator(cur, fid, "OPERATOR", "op2")
    with pytest.raises(ApiError) as exc:
        OperatorService().update_user(_ctx(fid, {"user_id": op, "role": "AUDITOR"}))
    assert exc.value.status == 403


def test_grievance_queue_rows_carry_grievance_id_and_resolution_carries_summary(tx):
    """GR-08: the console keys rows on grievance_id. GR-11: the resolution
    notice carries the summary itself."""
    from dpdpcms_py.services.compliance import GrievanceService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO grievances (user_id_enc, user_id_hmac, fiduciary_id, type, subject, description,"
            f" reference_number) VALUES ({_ASHA_ENC}, {_ASHA_HMAC}, %s, 'GENERAL_COMPLAINT', 's', 'd', 'GRV-2026-ABCDEF') RETURNING id",
            (fid,),
        )
        gid = str(cur.fetchone()["id"])
    service = GrievanceService()
    rows = service.list_grievances(_ctx(fid, {}))
    assert [str(r["grievance_id"]) for r in rows] == [gid]
    assert str(service.get_grievance(_ctx(fid, {"grievance_id": gid}))["grievance_id"]) == gid
    service.update_grievance_status(
        _ctx(fid, {"grievance_id": gid, "status": "RESOLVED", "resolution_details": "Record corrected."})
    )
    with tx.cursor() as cur:
        cur.execute(
            "SELECT context FROM notifications WHERE fiduciary_id = %s AND notification_type = 'GRIEVANCE_RESOLVED'",
            (fid,),
        )
        context = cur.fetchone()["context"]
    assert context["resolution_details"] == "Record corrected."
    assert context["reference_number"] == "GRV-2026-ABCDEF"


def test_internally_raised_alerts_are_audited(tx):
    """NT-10: record_alert (every consent and closure alert) writes an audit row."""
    from dpdpcms_py.services.lifecycle import record_alert

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    alert_id = record_alert(fid, "CONSENT_WITHDRAWN", None, {"user_id": "asha"})
    import json

    with tx.cursor() as cur:
        rows = [r for r in _audit_actions(cur, fid) if r["audit_action"] == "ALERT_RAISED"]
    assert len(rows) == 1
    details = rows[0]["context_details"]
    details = json.loads(details) if isinstance(details, str) else details
    assert details["alert_id"] == alert_id and "user_id" not in details


def test_retention_policy_delete_is_audited(tx):
    """SA-14: withdrawing a retention schedule leaves an audit trail."""
    from dpdpcms_py.services.retention import RetentionService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO retention_policies (fiduciary_id, name, retention_duration_value) VALUES (%s, 'r', 7) RETURNING id",
            (fid,),
        )
        pid = str(cur.fetchone()["id"])
    RetentionService().delete_retention_policy(_ctx(fid, {"policy_id": pid}))
    with tx.cursor() as cur:
        assert [r["audit_action"] for r in _audit_actions(cur, fid)] == ["RETENTION_POLICY_DELETED"]


def test_audit_export_carries_the_hashes_and_a_chain_verdict(tx, tmp_path, monkeypatch):
    """P9-08 / LG-07: an exported ledger can be re-verified by whoever receives it."""
    import csv
    import dataclasses
    import json

    from dpdpcms_py import jobs
    from dpdpcms_py.audit import log_event

    monkeypatch.setattr(jobs, "settings", dataclasses.replace(settings, export_path=tmp_path))
    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    log_event("asha", fid, "APP", None, "CONSENT_GIVEN", {"k": "v"})
    path = jobs._write_export({"id": str(uuid.uuid4()), "fiduciary_id": fid, "subtype": "AUDIT"})
    with path.open(encoding="utf-8") as handle:
        rows = [r for r in csv.DictReader(handle) if r["audit_action"] == "CONSENT_GIVEN"]
    assert len(rows) == 1 and len(rows[0]["current_log_hash"]) == 64 and "prev_log_hash" in rows[0]
    verdict = json.loads(path.with_suffix(".verification.json").read_text(encoding="utf-8"))
    assert "intact" in verdict


# ── workbook v8 (P10) remediation ─────────────────────────────────────────────
def _principal_ctx(fid, user, payload):
    return _ctx(fid, {"user_id": user, **payload}, auth_via_principal_jwt=True, principal_user_id=user)


def _confirm_ctx(fid, request_id):
    """INV-07: a purge completes only through confirm_purge_status, with evidence."""
    return _ctx(
        fid,
        {
            "purge_request_id": request_id,
            "status": "PURGE_COMPLETED",
            "records_affected_count": 1,
            "confirmed_by_entity_id": "dpo@example.org",
        },
    )


def _ctx_as(fid, role, payload, operator_id=None):
    from dpdpcms_py.context import RequestContext

    return RequestContext(
        path="/api/v1/admin/test",
        category="admin",
        service="test",
        payload=payload,
        headers={},
        fiduciary_id=fid,
        auth_token={"email": f"{role.lower()}@example.org", "role": role},
        operator_id=operator_id,
    )


def test_a_decision_naming_two_purposes_is_refused_and_aliases_are_canonical(tx):
    """P10-01: {purpose_id: care, id: research} was checked as one purpose and
    authorised the other. It is now refused; a lone alias is stored canonical."""
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("care",))
    service = ConsentService()
    with pytest.raises(ApiError) as exc:
        service.record_consent(
            _ctx(
                fid,
                {
                    "user_id": "asha",
                    "policy_id": pol,
                    "data_point_consents": [{"purpose_id": "care", "id": "research", "consent_granted": True}],
                },
            )
        )
    assert exc.value.status == 400
    service.record_consent(
        _ctx(
            fid,
            {"user_id": "asha", "policy_id": pol, "data_point_consents": [{"id": " CARE ", "consent_granted": True}]},
        )
    )
    with tx.cursor() as cur:
        points = _consents(cur, fid)["asha"]
    assert points == [{"data_point_id": "care", "consent_granted": True}]
    assert service.validate_consent(_ctx(fid, {"user_id": "asha", "required_purpose_id": "Care"}))["valid"] is True
    assert service.validate_consent(_ctx(fid, {"user_id": "asha", "required_purpose_id": "research"}))["valid"] is False


def _seed_policy_version(cur, fid, pol, version, status, purposes=("care",)):
    cur.execute(
        "INSERT INTO consent_policies (id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content)"
        " VALUES (%s, %s, %s, NOW(), %s, 'IN', %s)",
        (
            pol,
            version,
            fid,
            status,
            real_db.as_jsonb(
                {"en": {"title": "P", "data_processing_purposes": [{"id": p, "name": p} for p in purposes]}}
            ),
        ),
    )


def test_wording_only_notice_change_activates_and_reconsent_completes(tx):
    """P10-02: publish notified principals while the version was UNDER_REVIEW
    and request_reconsent was then refused. A version needing no new ROPA entry
    now activates at publish, and only then are principals asked."""
    from dpdpcms_py.services.catalog import PolicyService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        cur.execute(
            "INSERT INTO ropa_entries (fiduciary_id, activity_name, purpose, legal_basis, linked_policy_ids, source_purpose_id, status)"
            " VALUES (%s, 'care', 'care', 'consent', %s, 'care', 'active')",
            (fid, real_db.as_jsonb([pol])),
        )
        _seed_policy_version(cur, fid, pol, "v2", "DRAFT")
    out = PolicyService().publish_policy(_ctx(fid, {"policy_id": pol, "version": "v2"}))
    assert out["data"]["status"] == "ACTIVE"
    with tx.cursor() as cur:
        cur.execute(
            f"SELECT status FROM reconsent_requests WHERE fiduciary_id = %s AND user_id_hmac = {_ASHA_HMAC}", (fid,)
        )
        assert cur.fetchone()["status"] == "PENDING"
    granted = PolicyService().request_reconsent(
        _principal_ctx(
            fid,
            "asha",
            {
                "policy_id": pol,
                "version": "v2",
                "data_point_consents": [{"data_point_id": "care", "consent_granted": True}],
            },
        )
    )
    assert granted["status"] == "GRANTED"
    with tx.cursor() as cur:
        cur.execute(
            "SELECT policy_version FROM consent_records WHERE fiduciary_id = %s AND is_active_consent IS TRUE", (fid,)
        )
        assert [r["policy_version"] for r in cur.fetchall()] == ["v2"]


def test_version_with_new_ropa_entry_notifies_only_once_active(tx):
    """P10-02: while the version awaits its ROPA entry nobody is asked to
    re-consent; publishing the entry activates it and sends the notices."""
    from dpdpcms_py.services.catalog import PolicyService
    from dpdpcms_py.services.governance import RopaService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        _seed_policy_version(cur, fid, pol, "v2", "DRAFT", purposes=("care", "research"))
        cur.execute(
            "INSERT INTO ropa_entries (fiduciary_id, activity_name, purpose, legal_basis, linked_policy_ids, source_purpose_id)"
            " VALUES (%s, 'research', 'research', 'consent', %s, 'Research') RETURNING id, source_purpose_id",
            (fid, real_db.as_jsonb([pol])),
        )
        entry = cur.fetchone()
    assert entry["source_purpose_id"] == "research", "db/26 canonicalises the ROPA link"
    out = PolicyService().publish_policy(_ctx(fid, {"policy_id": pol, "version": "v2"}))
    assert out["data"]["status"] == "UNDER_REVIEW"
    with tx.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM reconsent_requests WHERE fiduciary_id = %s", (fid,))
        assert cur.fetchone()["n"] == 0
    RopaService().publish_entry(_ctx(fid, {"id": str(entry["id"])}))
    with tx.cursor() as cur:
        cur.execute("SELECT status FROM consent_policies WHERE id = %s AND version = 'v2'", (pol,))
        assert cur.fetchone()["status"] == "ACTIVE"
        cur.execute(
            "SELECT COUNT(*) AS n FROM notifications WHERE fiduciary_id = %s"
            " AND notification_type = 'POLICY_CHANGE_RECONSENT_REQUIRED'",
            (fid,),
        )
        assert cur.fetchone()["n"] == 1


def test_role_assignment_is_bounded_by_the_callers_permissions(tx):
    """P10-03: a custom role holding operator:write could assign DPO, to itself."""
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.admin import OperatorService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO roles (code, name, permissions, fiduciary_id) VALUES ('OPWRITER', 'Op writer', %s, %s)",
            (real_db.as_jsonb(["operator:read", "operator:write"]), fid),
        )
        me = _seed_operator(cur, fid, "OPWRITER", "me")
        other = _seed_operator(cur, fid, "OPERATOR", "other")
    service = OperatorService()
    for target in (me, other):
        with pytest.raises(ApiError) as exc:
            service.update_user(_ctx_as(fid, "OPWRITER", {"user_id": target, "role": "DPO"}, operator_id=me))
        assert exc.value.status == 403
    with pytest.raises(ApiError) as exc:
        service.create_user(
            _ctx_as(
                fid,
                "OPWRITER",
                {"role": "DPO", "username": "x", "email": "x@example.org", "password": "pw-0123456789"},
                operator_id=me,
            )
        )
    assert exc.value.status == 403
    # Assigning a role whose permissions the caller holds still works.
    service.update_user(_ctx_as(fid, "OPWRITER", {"user_id": other, "role": "OPWRITER"}, operator_id=me))
    with tx.cursor() as cur:
        cur.execute("SELECT role FROM operators WHERE id = %s", (other,))
        assert cur.fetchone()["role"] == "OPWRITER"


def test_statutory_hold_authored_in_one_case_governs_every_case(tx):
    """P10-04: a 7-year hold for 'marketing' was invisible to 'Marketing', so
    closing 'Marketing' erased immediately instead of deferring."""
    from dpdpcms_py.services.lifecycle import close_purpose_exec
    from dpdpcms_py.services.retention import legal_hold_for, retention_for

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("marketing",))
        _seed_consent(cur, fid, pol, "asha", purposes=("marketing",))
        cur.execute(
            "INSERT INTO retention_policies (fiduciary_id, name, applicable_purposes, retention_duration_value,"
            " retention_duration_unit, action_at_expiry, legal_reference)"
            " VALUES (%s, 'stat', %s, 7, 'YEARS', 'ERASE', 'Clinical Establishments Rules 2012')",
            (fid, real_db.as_jsonb(["Marketing "])),
        )
        cur.execute(
            "INSERT INTO purpose_lifecycle (fiduciary_id, purpose_id) VALUES (%s, 'MARKETING') RETURNING purpose_id",
            (fid,),
        )
        assert cur.fetchone()["purpose_id"] == "marketing"
        cur.execute("SELECT applicable_purposes FROM retention_policies WHERE fiduciary_id = %s", (fid,))
        assert cur.fetchone()["applicable_purposes"] == ["marketing"]
    assert retention_for(fid, "Marketing") == (2555, "CESSATION")
    assert legal_hold_for(fid, "Marketing")["days"] == 2555
    out = close_purpose_exec(fid, "Marketing")
    assert out["retention_deferred_days"] == 2555 and out["purge_requests_created"] == 0


def test_closure_raises_purges_for_principals_who_already_withdrew(tx):
    """PL-03: a principal who withdrew still has data held under the purpose."""
    from dpdpcms_py.services.lifecycle import close_purpose_exec

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        _seed_consent(cur, fid, pol, "never", granted=False)
        cur.execute(
            "INSERT INTO consent_records (id, user_id_enc, user_id_hmac, fiduciary_id, policy_id, policy_version,"
            " timestamp, jurisdiction, language_selected, data_point_consents, is_active_consent,"
            " consent_status_general, consent_mechanism, ip_address) VALUES (uuid_generate_v4(), %s, %s, %s, %s,"
            " 'v1', NOW(), 'IN', 'en', %s, FALSE, 'CONSENT_GIVEN', 'WEB', '1.2.3.4')",
            (*_pid(cur, "ramesh"), fid, pol, real_db.as_jsonb([{"data_point_id": "care", "consent_granted": True}])),
        )
        cur.execute("INSERT INTO purpose_lifecycle (fiduciary_id, purpose_id) VALUES (%s, 'care')", (fid,))
    out = close_purpose_exec(fid, "care")
    with tx.cursor() as cur:
        cur.execute(
            f"SELECT {real_db.decrypt_col('user_id_enc')} AS user_id FROM purge_requests WHERE fiduciary_id = %s"
            " ORDER BY 1",
            (*real_db.bind_key(), fid),
        )
        users = [r["user_id"] for r in cur.fetchall()]
    assert users == ["asha", "ramesh"] and out["purge_requests_created"] == 2


def test_audit_verdict_covers_exactly_the_exported_window(tx, tmp_path, monkeypatch):
    """P10-06: the verdict walked the newest rows of the whole ledger, not the
    exported range, and reported intact without checking coverage."""
    import dataclasses
    import json

    from dpdpcms_py import audit, jobs

    monkeypatch.setattr(jobs, "settings", dataclasses.replace(settings, export_path=tmp_path))
    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    audit.log_event("asha", fid, "APP", None, "CONSENT_GIVEN", {"k": "v"})
    window_start = datetime.now(UTC) - timedelta(days=1)
    window_end = datetime.now(UTC) + timedelta(days=1)
    full = audit.verify_chain(fiduciary_id=fid, since=window_start, until=window_end)
    assert full["coverage_complete"] is True and full["anchored_until"] is not None
    truncated = audit.verify_chain(limit=0, fiduciary_id=fid, since=window_start, until=window_end)
    assert truncated["coverage_complete"] is False
    # A walk that could not cover the window never attests an intact chain.
    real_verify = audit.verify_chain
    monkeypatch.setattr(audit, "verify_chain", lambda **kw: {**real_verify(**kw), "coverage_complete": False})
    path = jobs._write_export(
        {
            "id": str(uuid.uuid4()),
            "fiduciary_id": fid,
            "subtype": "AUDIT",
            "start_date": window_start.date(),
            "end_date": window_end.date(),
        }
    )
    verdict = json.loads(path.with_suffix(".verification.json").read_text(encoding="utf-8"))
    assert verdict["chain_intact"] is False and verdict["attestation"] == "NOT_ATTESTED"
    assert verdict["anchored_until"].startswith((window_end.date() + timedelta(days=1)).isoformat())


def test_console_audit_listing_carries_system_metadata(tx):
    """LG-07: without system_metadata the console XLSX cannot be re-verified."""
    from dpdpcms_py import audit

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    audit.log_event("asha", fid, "APP", None, "CONSENT_GIVEN", {"k": "v"})
    rows = audit.list_logs({"fiduciary_id": fid})
    assert rows and rows[0]["system_metadata"]["hash_v"]


def test_resolution_summary_stays_in_the_app(tx):
    """P10-07: the clinical resolution summary is never handed to SMS / push."""
    from dpdpcms_py.delivery import render_message

    context = {"reference_number": "GRV-1", "status_word": "resolved", "resolution_details": "Your HIV test record"}
    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    _s, in_app = render_message(fid, "GRIEVANCE_RESOLVED", "PRINCIPAL", context)
    _s, sms = render_message(fid, "GRIEVANCE_RESOLVED", "PRINCIPAL", context, channel="SMS")
    assert "HIV" in in_app
    assert "HIV" not in sms and "GRV-1" in sms and "sign in" in sms


def test_principal_self_check_is_audited_as_a_self_check(tx):
    """P10-08: the self-check left no trace; it is now logged as what it is."""
    import json

    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
    ConsentService().validate_consent(_principal_ctx(fid, "asha", {"required_purpose_id": "care"}))
    with tx.cursor() as cur:
        cur.execute("SELECT audit_action, initiator, context_details FROM audit_logs WHERE fiduciary_id = %s", (fid,))
        rows = cur.fetchall()
        cur.execute("SELECT COUNT(*) AS n FROM consent_validations WHERE fiduciary_id = %s", (fid,))
        validations = cur.fetchone()["n"]
    assert [(r["audit_action"], r["initiator"]) for r in rows] == [("CONSENT_SELF_CHECKED", "PRINCIPAL")]
    details = rows[0]["context_details"]
    assert (json.loads(details) if isinstance(details, str) else details)["purpose_status"] == "GRANTED"
    assert validations == 0


def test_every_server_notice_has_words_and_no_unfilled_placeholders(tx):
    """P10-10: three types delivered their enum name; a resolution notice
    without context delivered literal {placeholders}."""
    from dpdpcms_py.delivery import render_message
    from dpdpcms_py.services.governance import NotificationService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    for ntype in ("POLICY_CHANGE_RECONSENT_REQUIRED", "PURGE_SCHEDULED", "PURGE_EXECUTED", "SOMETHING_NEW"):
        _s, body = render_message(fid, ntype, "PRINCIPAL")
        assert ntype not in body and "{" not in body
    _s, body = render_message(fid, "GRIEVANCE_RESOLVED", "PRINCIPAL")
    assert "{" not in body and "resolved" in body
    out = NotificationService().dispatch_notification(
        _ctx(
            fid,
            {
                "recipient_type": "PRINCIPAL",
                "recipient_id": "asha",
                "notification_type": "GRIEVANCE_ROUTED",
                "context": {"reference_number": "GRV-9", "grievance_type": "GENERAL_COMPLAINT"},
            },
        )
    )
    with tx.cursor() as cur:
        cur.execute("SELECT context FROM notifications WHERE id = %s", (out["notification_id"],))
        context = cur.fetchone()["context"]
    _s, body = render_message(fid, "GRIEVANCE_ROUTED", "DPO", context)
    assert "GRV-9" in body and "{" not in body


def test_console_template_names_are_the_ones_the_engine_reads(tx):
    """NT-02 / NT-03: unknown types and unsupported language codes are refused."""
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.governance import NotificationService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    service = NotificationService()
    for payload in (
        {"notification_type": "GRIEVANCE_RESOLVED_NOTIFICATION", "messages": {"mr": "x"}},
        {"notification_type": "GRIEVANCE_RESOLVED", "messages": {"xx": "x"}},
    ):
        with pytest.raises(ApiError) as exc:
            service.set_notification_message(_ctx(fid, {"fiduciary_id": fid, **payload}))
        assert exc.value.status == 400
    service.set_notification_message(
        _ctx(fid, {"fiduciary_id": fid, "notification_type": "grievance_resolved", "messages": {"sat": "x"}})
    )
    service.set_notification_message(
        _ctx(fid, {"fiduciary_id": fid, "notification_type": "BREACH_NOTIFICATION_PHISHING", "messages": {"en": "y"}})
    )


def test_consent_under_two_policies_of_one_fiduciary(tx):
    """P10-11: the second policy's consent raised UniqueViolation (HTTP 500)."""
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol_a = _seed_tenant(cur)
        pol_b = f"{pol_a}-b"
        _seed_policy_version(cur, fid, pol_b, "v1", "ACTIVE", purposes=("research",))
    service = ConsentService()
    for pol, purpose in ((pol_a, "care"), (pol_b, "research")):
        service.record_consent(
            _ctx(
                fid,
                {
                    "user_id": "asha",
                    "policy_id": pol,
                    "data_point_consents": [{"data_point_id": purpose, "consent_granted": True}],
                },
            )
        )
    with tx.cursor() as cur:
        cur.execute(
            "SELECT policy_id FROM consent_records WHERE fiduciary_id = %s AND is_active_consent IS TRUE ORDER BY policy_id",
            (fid,),
        )
        assert [r["policy_id"] for r in cur.fetchall()] == sorted([pol_a, pol_b])


def test_login_returns_the_session_the_portal_reads(tx):
    """UD-05: principal_login returned none of the keys saveSession reads."""
    from dpdpcms_py.services.consent import PrincipalService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO ropa_entries (fiduciary_id, activity_name, purpose, legal_basis, data_subject_categories,"
            " linked_policy_ids, status) VALUES (%s, 'a', 'p', 'consent', %s, %s, 'active')",
            (fid, real_db.as_jsonb(["Patient Family"]), real_db.as_jsonb([pol])),
        )
    session = PrincipalService._portal_session(fid)
    assert session["fiduciary_name"].startswith("fid-")
    assert session["policies"] == [
        {"policy_id": pol, "version": "v1", "jurisdiction": "IN", "title": "P", "personas": ["patient_family"]}
    ]
    assert session["pca_qr_enabled"] is True


def test_withdrawal_fans_out_to_each_processor(tx, monkeypatch):
    """CW-08: one endpoint per category stood in for every processor."""
    from dpdpcms_py import webhooks
    from dpdpcms_py.services.alerts import AlertService
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        apps = []
        for name in ("lab", "pharmacy"):
            cur.execute(
                "INSERT INTO apps (fiduciary_id, name, status, dpa_reference) VALUES (%s, %s, 'ACTIVE', 'DPA-1')"
                " RETURNING id",
                (fid, name),
            )
            apps.append(str(cur.fetchone()["id"]))
            cur.execute(
                "INSERT INTO processor_webhook_configs (app_id, fiduciary_id, category, webhook_url, secret_enc)"
                " VALUES (%s, %s, 'NOTIFICATION', %s, '')",
                (apps[-1], fid, f"https://{name}.example.org/hook"),
            )
        # P11-05: an integrator app with no processor endpoint is not a processor.
        cur.execute("INSERT INTO apps (fiduciary_id, name, status) VALUES (%s, 'integrator', 'ACTIVE')", (fid,))
    out = ConsentService().withdraw_consent(_ctx(fid, {"user_id": "asha", "purpose_ids": ["care"]}))
    assert out["processors_notified"] == 2
    with tx.cursor() as cur:
        cur.execute(
            f"SELECT {real_db.decrypt_col('recipient_id_enc')} AS recipient_id, id FROM alerts"
            " WHERE fiduciary_id = %s AND recipient_type = 'PROCESSOR'",
            (*real_db.bind_key(), fid),
        )
        alerts = {r["recipient_id"]: str(r["id"]) for r in cur.fetchall()}
        cur.execute(
            "SELECT app_id FROM webhook_deliveries WHERE fiduciary_id = %s AND event_type = 'CONSENT_WITHDRAWN'"
            " AND app_id IS NOT NULL",
            (fid,),
        )
        addressed = {str(r["app_id"]) for r in cur.fetchall()}
    assert set(alerts) == set(apps) and addressed == set(apps)
    sent = []
    monkeypatch.setattr(webhooks, "_send", lambda delivery, config: sent.append(config["webhook_url"]) or (200, None))
    webhooks.process_pending_webhooks(limit=500)
    assert "https://lab.example.org/hook" in sent
    # One processor's key cannot acknowledge another processor's alert.
    from dpdpcms_py.errors import ApiError

    with pytest.raises(ApiError):
        AlertService().acknowledge_alert(_ctx(fid, {"alert_id": alerts[apps[1]]}, app_id=apps[0]))
    AlertService().acknowledge_alert(_ctx(fid, {"alert_id": alerts[apps[0]]}, app_id=apps[0]))


def test_multi_purpose_grant_logs_every_purpose_id(tx):
    """CU-09: the audit row names the purposes a multi-purpose grant decided."""
    import json

    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("care", "research"))
    ConsentService().record_consent(
        _ctx(
            fid,
            {
                "user_id": "asha",
                "policy_id": pol,
                "data_point_consents": [
                    {"data_point_id": "care", "consent_granted": True},
                    {"data_point_id": "research", "consent_granted": False},
                ],
            },
        )
    )
    with tx.cursor() as cur:
        rows = [r for r in _audit_actions(cur, fid) if r["audit_action"] == "CONSENT_GIVEN"]
    details = rows[0]["context_details"]
    details = json.loads(details) if isinstance(details, str) else details
    assert details["purpose_ids"] == ["care", "research"] and details["granted_purpose_ids"] == ["care"]


def test_grievance_notices_carry_the_language_it_was_filed_in(tx):
    """GR-03: a principal who files in Tamil is answered in Tamil."""
    from dpdpcms_py.services.compliance import GrievanceService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha", language="hi")
    out = GrievanceService().submit_grievance(
        _ctx(
            fid,
            {"user_id": "asha", "type": "GENERAL_COMPLAINT", "subject": "s", "description": "d", "language": "ta"},
        )
    )
    GrievanceService().update_grievance_status(
        _ctx(fid, {"grievance_id": out["grievance_id"], "status": "RESOLVED", "resolution_details": "done"})
    )
    with tx.cursor() as cur:
        cur.execute(
            "SELECT notification_type, context FROM notifications WHERE fiduciary_id = %s AND recipient_type = 'PRINCIPAL'",
            (fid,),
        )
        languages = {r["notification_type"]: (r["context"] or {}).get("language") for r in cur.fetchall()}
    assert languages["GRIEVANCE_SUBMITTED"] == "ta" and languages["GRIEVANCE_RESOLVED"] == "ta"


def test_maintenance_opt_in_cannot_forge_consent(tx):
    """P9-05 residual: the opt-in rewrites who a record names and its purpose
    entries, never deletes, revives, re-points or grants."""
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha", granted=False)
        real_db.allow_consent_maintenance(cur)
        for sql in (
            "DELETE FROM consent_records WHERE fiduciary_id = %s",
            "UPDATE consent_records SET policy_version = 'v9' WHERE fiduciary_id = %s",
            'UPDATE consent_records SET data_point_consents = \'[{"data_point_id": "care", "consent_granted": true}]\'::jsonb WHERE fiduciary_id = %s',
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege), tx.transaction():
                cur.execute(sql, (fid,))
        cur.execute(
            "UPDATE consent_records SET user_id_enc = encode(pgp_sym_encrypt('erased:x', current_setting('app.enc_key')), 'base64'),"
            " user_id_hmac = encode(hmac('erased:x', current_setting('app.enc_key'), 'sha256'), 'hex'),"
            " ip_address = '0.0.0.0' WHERE fiduciary_id = %s",
            (fid,),
        )
        assert cur.rowcount == 1


def test_erasure_token_cannot_be_recomputed_from_the_identifier(tx):
    """SA-13: the replacement is random, not a keyed hash of the identifier."""
    from dpdpcms_py.security import pseudonym
    from dpdpcms_py.services.compliance import erase_cms_copy

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        erase_cms_copy(fid, "asha", cur=cur, pending_files=set())
        cur.execute(
            f"SELECT {real_db.decrypt_col('user_id_enc')} AS user_id FROM consent_records WHERE fiduciary_id = %s",
            (*real_db.bind_key(), fid),
        )
        token = cur.fetchone()["user_id"]
    assert token.startswith("erased:") and token != f"erased:{pseudonym(f'{fid}:asha')}"


def test_no_processor_key_without_a_dpa(tx):
    """Rule 6(1)(f): a key for an app needs the app's recorded DPA."""
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.governance import ApiKeyService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute("INSERT INTO apps (fiduciary_id, name) VALUES (%s, 'lab') RETURNING id", (fid,))
        app = str(cur.fetchone()["id"])
    with pytest.raises(ApiError) as exc:
        ApiKeyService().generate_api_key(_ctx(fid, {"fiduciary_id": fid, "app_id": app}))
    assert exc.value.status == 400
    with tx.cursor() as cur:
        cur.execute("UPDATE apps SET dpa_reference = 'DPA-2026-01' WHERE id = %s", (app,))
    assert ApiKeyService().generate_api_key(_ctx(fid, {"fiduciary_id": fid, "app_id": app}))["success"] is True


def test_pending_grievance_queue_carries_grievance_id(tx):
    """GR-08: the fourth reader, the dashboard's pending queue."""
    from dpdpcms_py.services.admin import AdminDashService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO grievances (user_id_enc, user_id_hmac, fiduciary_id, type, subject, description)"
            f" VALUES ({_ASHA_ENC}, {_ASHA_HMAC}, %s, 'GENERAL_COMPLAINT', 's', 'd') RETURNING id",
            (fid,),
        )
        gid = str(cur.fetchone()["id"])
    rows = AdminDashService().list_pending_grievances(_ctx(fid, {"fiduciary_id": fid}))
    assert [str(r["grievance_id"]) for r in rows] == [gid]


def test_failed_signin_burst_raises_one_alert_per_window(tx):
    """Rule 6(1)(c): the ledger is watched - a burst of failed sign-ins alerts the DPO once."""
    from dpdpcms_py import jobs
    from dpdpcms_py.audit import log_event

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    for _ in range(jobs.SECURITY_FAILURE_THRESHOLD):
        log_event("mallory", fid, "APP", None, "PRINCIPAL_LOGIN_FAILURE", {"reason": "bad otp"})
    assert jobs.flag_security_anomalies()["alerts_raised"] >= 1
    jobs.flag_security_anomalies()
    with tx.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE fiduciary_id = %s AND alert_type = 'SECURITY_AUTH_FAILURE_BURST'",
            (fid,),
        )
        alerts = cur.fetchone()["n"]
        cur.execute(
            "SELECT context FROM notifications WHERE fiduciary_id = %s AND notification_type = 'SECURITY_AUTH_FAILURE_BURST'",
            (fid,),
        )
        context = cur.fetchone()["context"]
    assert alerts == 1 and context["failures"] == jobs.SECURITY_FAILURE_THRESHOLD


def test_consent_history_filters_by_purpose_status_and_date(tx):
    """UD-03: the principal can search and filter their consent history."""
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("care", "research"))
        _seed_consent(cur, fid, pol, "asha", purposes=("care",))
    ConsentService().withdraw_consent(_ctx(fid, {"user_id": "asha", "purpose_ids": ["care"]}))
    history = ConsentService().list_consent_history
    assert len(history(_principal_ctx(fid, "asha", {}))) == 2
    assert len(history(_principal_ctx(fid, "asha", {"purpose_id": "CARE"}))) == 2
    assert history(_principal_ctx(fid, "asha", {"purpose_id": "research"})) == []
    withdrawn = history(_principal_ctx(fid, "asha", {"status": "WITHDRAWN"}))
    assert [r["consent_status_general"] for r in withdrawn] == ["WITHDRAWN"]
    assert history(_principal_ctx(fid, "asha", {"end_date": "2000-01-01T00:00:00"})) == []


def test_padded_purpose_id_cannot_slip_past_the_closed_gate(tx):
    """P10-04: ' care' matched the grant but missed the CLOSED lifecycle row."""
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        cur.execute(
            "INSERT INTO purpose_lifecycle (fiduciary_id, purpose_id, state) VALUES (%s, 'care', 'CLOSED')", (fid,)
        )
    for asked in (" care", "CARE ", "care"):
        out = ConsentService().validate_consent(_ctx(fid, {"user_id": "asha", "required_purpose_id": asked}))
        assert out["valid"] is False and out["metadata"]["purpose_status"] == "PURPOSE_CLOSED"
    with tx.cursor() as cur:
        cur.execute("SELECT DISTINCT purpose_id FROM consent_validations WHERE fiduciary_id = %s", (fid,))
        assert [r["purpose_id"] for r in cur.fetchall()] == ["care"]


def test_processor_key_lists_only_its_own_processor_alerts(tx):
    """CW-08: processor alerts carry user ids; one processor never lists another's."""
    from dpdpcms_py.services.alerts import AlertService
    from dpdpcms_py.services.lifecycle import record_alert

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        apps = []
        for name in ("lab", "pharmacy"):
            cur.execute("INSERT INTO apps (fiduciary_id, name) VALUES (%s, %s) RETURNING id", (fid, name))
            apps.append(str(cur.fetchone()["id"]))
    for app in apps:
        record_alert(fid, "CONSENT_WITHDRAWN", None, {"user_id": "asha"}, recipient_type="PROCESSOR", recipient_id=app)
    record_alert(fid, "CONSENT_WITHDRAWN", None, {})
    rows = AlertService().list_alerts(_ctx(fid, {}, app_id=apps[0]))
    assert sorted(r["recipient_type"] for r in rows) == ["FIDUCIARY", "PROCESSOR"]
    assert all(r["recipient_id"] != apps[1] for r in rows)
