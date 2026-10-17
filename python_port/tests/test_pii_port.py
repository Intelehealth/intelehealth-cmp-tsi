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
        enc, h = _enc_hmac(cur, "asha")
        cur.execute(
            "INSERT INTO grievances (id, user_id_enc, user_id_hmac, fiduciary_id, type, subject, description, status)"
            " VALUES (uuid_generate_v4(), %s, %s, %s, 'GENERAL_COMPLAINT', 's', 'd', 'NEW') RETURNING channel",
            (enc, h, fid),
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


def _archive_everything(monkeypatch):
    """Archive every yearly partition (now far enough ahead that none stays live)."""
    import dataclasses
    from datetime import UTC, datetime

    from dpdpcms_py import jobs

    monkeypatch.setattr(jobs, "settings", dataclasses.replace(jobs.settings, audit_live_years=1))
    return jobs.archive_audit_partitions(datetime(2200, 6, 1, tzinfo=UTC))


@needs_db
def test_chain_continues_from_archive_when_live_ledger_is_empty(tx, monkeypatch):
    from datetime import datetime

    from dpdpcms_py import audit

    with tx.cursor() as cur:
        year = _live_partition_years(cur)[0]
    _log_at(monkeypatch, datetime(year, 3, 1))
    _log_at(monkeypatch, datetime(year, 3, 2))
    _archive_everything(monkeypatch)
    with tx.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM audit_logs")
        assert cur.fetchone()["n"] == 0, "live ledger should be empty after archiving every year"
        cur.execute(f"SELECT current_log_hash FROM audit_logs_y{year}_archive ORDER BY timestamp DESC, id DESC LIMIT 1")
        newest_archived = cur.fetchone()["current_log_hash"]

    _log_at(monkeypatch, datetime(2200, 6, 1))
    with tx.cursor() as cur:
        cur.execute("SELECT prev_log_hash FROM audit_logs")
        assert cur.fetchone()["prev_log_hash"] == newest_archived
    chain = audit.verify_chain()
    assert chain["intact"] is True and chain["rows_checked"] >= 3


@needs_db
def test_archive_tables_keep_tenant_isolation(tx, monkeypatch):
    from datetime import datetime

    from dpdpcms_py import audit

    with tx.cursor() as cur:
        year = _live_partition_years(cur)[0]
        fid_a, _ = _seed_tenant(cur)
        fid_b, _ = _seed_tenant(cur)
    _log_at(monkeypatch, datetime(year, 3, 1), fid=fid_a)
    _log_at(monkeypatch, datetime(year, 3, 2), fid=fid_b)
    _archive_everything(monkeypatch)
    archive = f"audit_logs_y{year}_archive"
    source = audit.ledger_source()
    assert archive in source
    with tx.cursor() as cur:
        cur.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = %s::regclass", (f"public.{archive}",)
        )
        archived_flags = cur.fetchone()
        cur.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = 'public.audit_logs'::regclass"
        )
        assert archived_flags == cur.fetchone()
        cur.execute("SELECT policyname FROM pg_policies WHERE schemaname = 'public' AND tablename = %s", (archive,))
        assert {r["policyname"] for r in cur.fetchall()} == {"tsi_unrestricted", "tsi_tenant_isolation"}
        cur.execute(
            "INSERT INTO tsi_reader_tenants (role_name, tenant_id) VALUES ('tsi_tenant_reader', %s)"
            " ON CONFLICT DO NOTHING",
            (fid_b,),
        )
        cur.execute("SET LOCAL ROLE tsi_tenant_reader")
        cur.execute(
            f"SELECT fiduciary_id::text AS fid FROM {source} WHERE fiduciary_id IN (%s, %s)",
            (fid_a, fid_b),
        )
        seen = [r["fid"] for r in cur.fetchall()]
        cur.execute("RESET ROLE")
    assert seen == [fid_b]


# ---- Task 3: principal-ID crypto and masking primitives ------------------------------


def test_pid_hmac_trims_but_keeps_case():
    from dpdpcms_py import pii

    assert pii.hmac_hex(" ABC ") == pii.hmac_hex("ABC") != pii.hmac_hex("abc")


def test_normalize_strips_spaces_only_like_sql_trim():
    from dpdpcms_py import pii

    assert pii.normalize("  a b  ") == "a b"
    assert pii.normalize("\tx\n") == "\tx\n"
    assert pii.normalize(None) is None


def test_mask_email_phone_other():
    from dpdpcms_py.pii import mask

    assert mask("satish@test.com") == "s***@t***.com"
    assert mask("+919876543210") == "+91********10"
    assert mask("AB1234") == "AB***"
    assert mask("erased:9f") == "erased"
    assert mask(None) is None
    assert mask("") == ""


def test_principal_view_masks_only_for_operators():
    from dpdpcms_py.context import RequestContext
    from dpdpcms_py.pii import principal_view

    def ctx(**kw):
        return RequestContext(path="/p", category="admin", service="s", payload={}, headers={}, **kw)

    assert principal_view(ctx(operator_id="op1"), "satish@test.com") == "s***@t***.com"
    assert principal_view(ctx(), "satish@test.com") == "satish@test.com"
    assert principal_view(ctx(operator_id="op1"), None) is None


def test_params_normalise_and_append_key():
    from dpdpcms_py import pii
    from dpdpcms_py.config import settings

    assert pii.hmac_params(" a ") == ("a", settings.db_encryption_key)
    assert pii.enc_params(None) == (None, settings.db_encryption_key)
    assert pii.dec_sql("c") == "pgp_sym_decrypt(decode(c, 'base64'), %s)"


@needs_db
def test_python_and_sql_hmac_agree(tx):
    from dpdpcms_py import pii
    from dpdpcms_py.config import settings

    # Postgres trim() strips spaces only; the tab/newline value proves Python agrees.
    for value in (" x@y.z ", "\t x@y.z\n ", "ABC"):
        with tx.cursor() as cur:
            cur.execute(f"SELECT {pii.HMAC_SQL} AS h", (value, settings.db_encryption_key))
            assert cur.fetchone()["h"] == pii.hmac_hex(value)


# ---- Task 4: principal identifiers stored encrypted with HMAC lookup keys -----------

# Every plaintext principal-identifier column db/34 replaces, with whether the
# source column was nullable (the _enc/_hmac pair mirrors it).
ENCRYPTED_PRINCIPAL_COLUMNS = {
    ("consent_records", "user_id"): False,
    ("data_principal", "user_id"): False,
    ("data_principal", "guardian_id"): True,
    ("grievances", "user_id"): False,
    ("purge_requests", "user_id"): False,
    ("consent_validations", "user_id"): False,
    ("breach_affected_principals", "user_id"): False,
    ("parental_verification_logs", "child_principal_id"): False,
    ("parental_verification_logs", "guardian_principal_id"): False,
    ("notifications", "recipient_id"): False,
    ("data_correction_requests", "user_id"): False,
    ("reconsent_requests", "user_id"): False,
    ("notification_deliveries", "recipient"): True,
    ("nominations", "nominating_principal_id"): False,
    ("nominations", "nominated_principal_id"): False,
    ("alerts", "recipient_id"): True,
    ("evidence_certificates", "subject_principal_id"): False,
    ("alerts", "acknowledged_by"): True,
    ("grievance_attachments", "uploaded_by"): False,
}


def _columns(cur, table):
    cur.execute(
        "SELECT column_name, is_nullable FROM information_schema.columns"
        " WHERE table_schema = 'public' AND table_name = %s",
        (table,),
    )
    return {r["column_name"]: r["is_nullable"] == "YES" for r in cur.fetchall()}


@needs_db
def test_no_plaintext_principal_columns_remain(tx):
    with tx.cursor() as cur:
        for (table, col), nullable in ENCRYPTED_PRINCIPAL_COLUMNS.items():
            cols = _columns(cur, table)
            assert col not in cols, f"{table}.{col} is still plaintext"
            assert cols.get(f"{col}_enc") is nullable, f"{table}.{col}_enc missing or wrong nullability"
            assert cols.get(f"{col}_hmac") is nullable, f"{table}.{col}_hmac missing or wrong nullability"


def _key_columns(cur, index_or_constraint_sql, params):
    cur.execute(index_or_constraint_sql, params)
    row = cur.fetchone()
    assert row, f"no key found for {params}"
    return row


@needs_db
def test_hmac_keys_replace_plaintext_keys(tx):
    with tx.cursor() as cur:
        pk = (
            "SELECT array_agg(a.attname::text ORDER BY k.ord) AS cols FROM pg_constraint c"
            " CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)"
            " JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum"
            " WHERE c.conrelid = %s::regclass AND c.contype = %s"
            " GROUP BY c.oid"
        )
        assert _key_columns(cur, pk, ("public.data_principal", "p"))["cols"] == ["user_id_hmac", "fiduciary_id"]
        assert _key_columns(cur, pk, ("public.breach_affected_principals", "p"))["cols"] == [
            "breach_id",
            "user_id_hmac",
        ]
        assert _key_columns(cur, pk, ("public.reconsent_requests", "u"))["cols"] == [
            "fiduciary_id",
            "policy_id",
            "policy_version",
            "user_id_hmac",
        ]
        cur.execute(
            "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND tablename = 'consent_records'"
            " AND indexdef LIKE 'CREATE UNIQUE INDEX%%' AND indexdef LIKE '%%is_active_consent%%'"
        )
        defs = [r["indexdef"] for r in cur.fetchall()]
        assert defs and all("(user_id_hmac, fiduciary_id, policy_id)" in d for d in defs), defs
        # No index anywhere still keys on a dropped plaintext column.
        for (table, col), _ in ENCRYPTED_PRINCIPAL_COLUMNS.items():
            cur.execute(
                "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' AND tablename = %s AND indexdef ~ %s",
                (table, rf"[(, ]{col}[,) ]"),
            )
            assert cur.fetchall() == [], f"index on {table}.{col} survived"


def _enc_hmac(cur, value):
    from dpdpcms_py import pii
    from dpdpcms_py.config import settings

    key = settings.db_encryption_key
    cur.execute(f"SELECT {pii.ENC_SQL} AS e, {pii.HMAC_SQL} AS h", (value, key, value, key))
    row = cur.fetchone()
    return row["e"], row["h"]


@needs_db
def test_consent_maintenance_rekeys_encrypted_user_id_only(tx):
    """The append-only trigger's maintenance branch (erasure) now ignores the
    encrypted pair instead of the dropped plaintext user_id."""
    import psycopg

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        enc, h = _enc_hmac(cur, "asha")
        cur.execute(
            "INSERT INTO consent_records (id, user_id_enc, user_id_hmac, fiduciary_id, policy_id, policy_version,"
            " timestamp, jurisdiction, language_selected, data_point_consents, is_active_consent,"
            " consent_status_general, consent_mechanism, ip_address, created_at, last_updated_at)"
            " VALUES (uuid_generate_v4(), %s, %s, %s, %s, 'v1', NOW(), 'IN', 'en', '[]', TRUE,"
            " 'CONSENT_GIVEN', 'WEB', '1.2.3.4', NOW(), NOW()) RETURNING id",
            (enc, h, fid, pol),
        )
        rid = cur.fetchone()["id"]
        new_enc, new_h = _enc_hmac(cur, "erased:tok")
        with pytest.raises(psycopg.errors.InsufficientPrivilege), tx.transaction():
            cur.execute("UPDATE consent_records SET user_id_hmac = %s WHERE id = %s", (new_h, rid))
        cur.execute("SELECT set_config('tsi.consent_maintenance', 'on', true)")
        cur.execute(
            "UPDATE consent_records SET user_id_enc = %s, user_id_hmac = %s WHERE id = %s", (new_enc, new_h, rid)
        )
        cur.execute("SELECT user_id_hmac FROM consent_records WHERE id = %s", (rid,))
        assert cur.fetchone()["user_id_hmac"] == new_h


@needs_db
def test_delivery_floor_allows_only_encrypted_erasure_of_recipient(tx):
    import psycopg

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        enc, h = _enc_hmac(cur, "asha")
        cur.execute(
            "INSERT INTO notifications (recipient_type, recipient_id_enc, recipient_id_hmac, fiduciary_id,"
            " notification_type) VALUES ('PRINCIPAL', %s, %s, %s, 'CONSENT_RECORDED') RETURNING id",
            (enc, h, fid),
        )
        nid = cur.fetchone()["id"]
        r_enc, r_h = _enc_hmac(cur, "+911234")
        cur.execute(
            "INSERT INTO notification_deliveries (notification_id, channel, recipient_enc, recipient_hmac)"
            " VALUES (%s, 'SMS', %s, %s) RETURNING id",
            (nid, r_enc, r_h),
        )
        did = cur.fetchone()["id"]
        other_enc, other_h = _enc_hmac(cur, "+919999")
        with pytest.raises(psycopg.errors.RaiseException, match="recipient"), tx.transaction():
            cur.execute(
                "UPDATE notification_deliveries SET recipient_enc = %s, recipient_hmac = %s WHERE id = %s",
                (other_enc, other_h, did),
            )
        with pytest.raises(psycopg.errors.RaiseException, match="recipient"), tx.transaction():
            cur.execute("UPDATE notification_deliveries SET recipient_enc = NULL WHERE id = %s", (did,))
        e_enc, e_h = _enc_hmac(cur, "erased:abc")
        cur.execute(
            "UPDATE notification_deliveries SET recipient_enc = %s, recipient_hmac = %s, status = 'SENT' WHERE id = %s",
            (e_enc, e_h, did),
        )
        cur.execute("SELECT recipient_hmac, status FROM notification_deliveries WHERE id = %s", (did,))
        assert cur.fetchone() == {"recipient_hmac": e_h, "status": "SENT"}


# ---- Task 5: consent, principal and wallet services on the encrypted columns --------


def _api_ctx(fid, payload):
    """An integrator API-key caller of `fid` (no operator, no principal token)."""
    from dpdpcms_py.context import RequestContext

    return RequestContext(
        path="/api/v1/consent",
        category="client",
        service="consent",
        payload=payload,
        headers={},
        fiduciary_id=fid,
        permissions={"READ", "WRITE"},
        app_id="app-1",
    )


def _grant(fid, pol, user, purpose="care"):
    from dpdpcms_py.services.consent import ConsentService

    return ConsentService().record_consent(
        _api_ctx(
            fid,
            {"user_id": user, "policy_id": pol, "data_point_consents": [{"id": purpose, "consent_granted": True}]},
        )
    )


@needs_db
def test_record_list_withdraw_consent_round_trip_encrypted(tx):
    from dpdpcms_py import pii
    from dpdpcms_py.config import settings
    from dpdpcms_py.services.consent import ConsentService

    pid = "satish@test.com"
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
    _grant(fid, pol, pid)
    service = ConsentService()

    active = service.get_active_consent(_api_ctx(fid, {"user_id": pid}))
    assert active["user_id"] == pid
    assert "user_id_enc" not in active and "user_id_hmac" not in active
    assert all(r["user_id"] == pid for r in active["active_records"])

    listed = service.list_consents(_ctx(fid, {}, operator_id="op-1"))["data"]
    assert [r["user_id"] for r in listed] == [pii.mask(pid)]
    # The console search matches the whole identifier through its HMAC.
    assert len(service.list_consents(_ctx(fid, {"user_id": f" {pid} "}, operator_id="op-1"))["data"]) == 1
    assert service.list_consents(_ctx(fid, {"user_id": "satish"}, operator_id="op-1"))["data"] == []

    out = service.withdraw_consent(_api_ctx(fid, {"user_id": pid, "purpose_ids": ["care"]}))
    assert out["success"] is True
    history = service.list_consent_history(_api_ctx(fid, {"user_id": pid}))
    # One test transaction: both rows carry the same NOW(), so compare unordered.
    assert sorted(r["consent_status_general"] for r in history) == ["CONSENT_GIVEN", "WITHDRAWN"]
    assert {r["user_id"] for r in history} == {pid}

    with tx.cursor() as cur:
        for table in ("consent_records", "data_principal", "notifications"):
            cur.execute(f"SELECT to_jsonb(t)::text AS j FROM {table} t WHERE fiduciary_id = %s", (fid,))
            rows = cur.fetchall()
            assert rows, f"no {table} rows written"
            assert all(pid not in r["j"] for r in rows), f"plaintext principal id stored in {table}"
        cur.execute(
            f"SELECT {pii.dec_sql('user_id_enc')} AS u, user_id_hmac FROM consent_records WHERE fiduciary_id = %s",
            (settings.db_encryption_key, fid),
        )
        assert {(r["u"], r["user_id_hmac"]) for r in cur.fetchall()} == {(pid, pii.hmac_hex(pid))}


@needs_db
def test_principal_ids_with_spaces_resolve_and_case_stays_distinct(tx):
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
    service = ConsentService()
    _grant(fid, pol, " a@b.com ")
    active = service.get_active_consent(_api_ctx(fid, {"user_id": "a@b.com"}))
    assert active["user_id"] == "a@b.com"
    assert service.validate_consent(_api_ctx(fid, {"user_id": "a@b.com", "required_purpose_id": "care"}))["valid"]

    _grant(fid, pol, "ABC123")
    assert service.get_active_consent(_api_ctx(fid, {"user_id": "ABC123"}))["user_id"] == "ABC123"
    with pytest.raises(ApiError) as err:
        service.get_active_consent(_api_ctx(fid, {"user_id": "abc123"}))
    assert err.value.status == 404
    _grant(fid, pol, "abc123")
    assert service.get_active_consent(_api_ctx(fid, {"user_id": "abc123"}))["user_id"] == "abc123"
    with tx.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM data_principal WHERE fiduciary_id = %s", (fid,))
        assert cur.fetchone()["n"] == 3
