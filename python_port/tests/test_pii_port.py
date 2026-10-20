"""Ports of Consent-Manager's PII and audit features.

DB-backed tests reuse the transaction-per-test fixture and seed helpers of
test_integration_db.py and skip without a live Postgres; the rest are unit
tests.
"""

import uuid

import pytest
from tests.test_integration_db import _DB_READY, _ctx, _pid, _seed_tenant

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

    assert pii.hmac_params(" a ") == ("a", settings.pii_lookup_key)
    assert pii.enc_params(None) == (None, settings.db_encryption_key)
    assert pii.dec_sql("c") == "pgp_sym_decrypt(decode(c, 'base64'), %s)"


@needs_db
def test_python_and_sql_hmac_agree(tx):
    from dpdpcms_py import pii
    from dpdpcms_py.config import settings

    # Postgres trim() strips spaces only; the tab/newline value proves Python agrees.
    for value in (" x@y.z ", "\t x@y.z\n ", "ABC"):
        with tx.cursor() as cur:
            cur.execute(f"SELECT {pii.HMAC_SQL} AS h", (value, settings.pii_lookup_key))
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
    cur.execute(f"SELECT {pii.ENC_SQL} AS e, {pii.HMAC_SQL} AS h", (value, key, value, settings.pii_lookup_key))
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
            " consent_status_general, consent_mechanism, ip_address_enc, created_at, last_updated_at)"
            " VALUES (uuid_generate_v4(), %s, %s, %s, %s, 'v1', NOW(), 'IN', 'en', '[]', TRUE,"
            " 'CONSENT_GIVEN', 'WEB', encode(pgp_sym_encrypt('1.2.3.4', current_setting('app.enc_key')), 'base64'),"
            " NOW(), NOW()) RETURNING id",
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


# ---- Task 6: compliance (purge, grievance, breach, erasure) on the encrypted columns --


def _processor_ctx(fid, payload):
    """A PURGE-scope processor API key of `fid` (app bound, no operator)."""
    from dpdpcms_py.context import RequestContext

    return RequestContext(
        path="/api/v1/compliance",
        category="client",
        service="compliance",
        payload=payload,
        headers={},
        fiduciary_id=fid,
        permissions={"PURGE"},
        app_id="app-1",
    )


def _no_plaintext(cur, fid, pid, tables):
    for table in tables:
        cur.execute(f"SELECT to_jsonb(t)::text AS j FROM {table} t WHERE fiduciary_id = %s", (fid,))
        assert all(pid not in r["j"] for r in cur.fetchall()), f"plaintext principal id stored in {table}"


@needs_db
def test_erasure_writes_encrypted_placeholder_and_is_repeatable(tx):
    from dpdpcms_py import pii
    from dpdpcms_py.config import settings
    from dpdpcms_py.services.compliance import GrievanceService, erase_cms_copy
    from tests.test_integration_db import _seed_consent

    pid = "asha@example.org"
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, pid, ip="9.9.9.9", user_agent="curl/8")
        _seed_consent(cur, fid, pol, "ramesh@example.org", ip="1.2.3.5")
    GrievanceService().submit_grievance(
        _api_ctx(fid, {"user_id": pid, "type": "GENERAL_COMPLAINT", "subject": "s", "description": "d"})
    )
    with tx.cursor() as cur:
        cur.execute(
            "SELECT id FROM notifications WHERE fiduciary_id = %s AND recipient_id_hmac = %s",
            (fid, pii.hmac_hex(pid)),
        )
        nid = cur.fetchone()["id"]
        r_enc, r_h = _enc_hmac(cur, pid)
        cur.execute(
            "INSERT INTO notification_deliveries (notification_id, channel, recipient_enc, recipient_hmac)"
            " VALUES (%s, 'EMAIL', %s, %s)",
            (nid, r_enc, r_h),
        )

    counts = erase_cms_copy(fid, f" {pid} ")
    assert counts["consent_records"] == 1 and counts["grievances"] == 1
    assert counts["notification_deliveries"] == 1 and counts["consent_records.metadata"] == 1

    key = settings.db_encryption_key
    with tx.cursor() as cur:
        cur.execute(
            f"SELECT {pii.dec_sql('user_id_enc')} AS u, user_id_hmac, {pii.dec_sql('ip_address_enc')} AS ip_address,"
            " user_agent FROM consent_records WHERE fiduciary_id = %s",
            (key, key, fid),
        )
        rows = {r["u"]: r for r in cur.fetchall()}
        erased = [u for u in rows if u.startswith("erased:")]
        assert len(erased) == 1 and "ramesh@example.org" in rows
        token = erased[0]
        assert rows[token]["user_id_hmac"] == pii.hmac_hex(token)
        assert str(rows[token]["ip_address"]) == "0.0.0.0" and rows[token]["user_agent"] is None
        assert str(rows["ramesh@example.org"]["ip_address"]) == "1.2.3.5"
        for table, col in (("grievances", "user_id"), ("notifications", "recipient_id")):
            cur.execute(
                f"SELECT {pii.dec_sql(col + '_enc')} AS u, {col}_hmac AS h FROM {table} WHERE fiduciary_id = %s",
                (key, fid),
            )
            assert {(r["u"], r["h"]) for r in cur.fetchall()} == {(token, pii.hmac_hex(token))}
        cur.execute(
            f"SELECT {pii.dec_sql('recipient_enc')} AS u, recipient_hmac AS h FROM notification_deliveries"
            " WHERE notification_id = %s",
            (key, nid),
        )
        assert cur.fetchone() == {"u": token, "h": pii.hmac_hex(token)}
        _no_plaintext(cur, fid, pid, ("consent_records", "grievances", "notifications"))

    # A second erasure (the principal re-requests, or a retry) must neither
    # fail on the append-only / delivery-floor triggers nor re-key anything.
    again = erase_cms_copy(fid, pid)
    assert again["consent_records"] == 0 and again["consent_records.metadata"] == 0
    with tx.cursor() as cur:
        cur.execute(
            f"SELECT {pii.dec_sql('user_id_enc')} AS u FROM consent_records WHERE fiduciary_id = %s", (key, fid)
        )
        assert {r["u"] for r in cur.fetchall()} == {token, "ramesh@example.org"}


@needs_db
def test_processor_sees_plaintext_purge_user_id_operator_sees_mask(tx):
    from dpdpcms_py import pii
    from dpdpcms_py.services.compliance import ComplianceService
    from tests.test_integration_db import _seed_consent, _seed_purge

    pid = "asha@example.org"
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, pid)
        first = _seed_purge(cur, fid, pid, "care", action="DE_IDENTIFY")
        second = _seed_purge(cur, fid, pid, "care", action="DE_IDENTIFY")
    service = ComplianceService()
    operator = _ctx(fid, {}, operator_id="op-1")

    for row in service.list_purge_requests(_processor_ctx(fid, {})):
        assert row["user_id"] == pid and "user_id_enc" not in row and "user_id_hmac" not in row
    assert {r["user_id"] for r in service.list_purge_requests(operator)} == {pii.mask(pid)}
    assert service.get_purge_request(_processor_ctx(fid, {"id": first}))["user_id"] == pid
    got = service.get_purge_request(_ctx(fid, {"id": first}, operator_id="op-1"))
    assert got["user_id"] == pii.mask(pid) and "user_id_enc" not in got

    confirm = {"status": "PURGE_COMPLETED", "records_affected_count": 1}
    out = service.confirm_purge_status(_processor_ctx(fid, {**confirm, "purge_request_id": first}))
    assert out["status"] == "PURGE_COMPLETED" and out["user_id"] == pid
    assert out["cms_copy_erased"] == {"consent_records_touched": 1}
    out = service.confirm_purge_status(_ctx(fid, {**confirm, "purge_request_id": second}, operator_id="op-1"))
    assert out["user_id"] == pii.mask(pid)
    with tx.cursor() as cur:
        _no_plaintext(cur, fid, pid, ("purge_requests",))


@needs_db
def test_grievance_search_by_principal_is_exact_match(tx):
    from dpdpcms_py import pii
    from dpdpcms_py.services.compliance import GrievanceService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    service = GrievanceService()
    for user in ("asha@example.org", "asha@example.org.in", "Asha@example.org"):
        service.submit_grievance(
            _api_ctx(fid, {"user_id": user, "type": "GENERAL_COMPLAINT", "subject": "s", "description": "d"})
        )

    def search(term):
        return service.list_grievances(_ctx(fid, {"user_id": term}, operator_id="op-1"))

    found = search(" asha@example.org ")
    assert [g["user_id"] for g in found] == [pii.mask("asha@example.org")]
    assert "user_id_enc" not in found[0] and "user_id_hmac" not in found[0]
    assert search("asha") == []
    assert len(service.list_grievances(_ctx(fid, {}, operator_id="op-1"))) == 3

    mine = service.list_user_grievances(_api_ctx(fid, {"user_id": "asha@example.org"}))
    assert [g["user_id"] for g in mine] == ["asha@example.org"]
    detail = service.get_grievance(_api_ctx(fid, {"grievance_id": mine[0]["grievance_id"]}))
    assert detail["user_id"] == "asha@example.org" and "user_id_enc" not in detail
    with tx.cursor() as cur:
        _no_plaintext(cur, fid, "asha@example.org", ("grievances", "notifications"))


@needs_db
def test_principal_grievance_log_entry_names_no_principal_id(tx):
    from dpdpcms_py.context import RequestContext
    from dpdpcms_py.services.compliance import GrievanceService

    pid = "asha@example.org"
    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    service = GrievanceService()
    gid = service.submit_grievance(
        _api_ctx(fid, {"user_id": pid, "type": "GENERAL_COMPLAINT", "subject": "s", "description": "d"})
    )["grievance_id"]
    principal = RequestContext(
        path="/api/v1/rights",
        category="client",
        service="grievance",
        payload={"grievance_id": gid, "message": "any update?"},
        headers={},
        fiduciary_id=fid,
        principal_user_id=pid,
        auth_via_principal_jwt=True,
    )
    assert service.add_grievance_communication(principal)["entry"]["by"] == "PRINCIPAL"
    with tx.cursor() as cur:
        cur.execute("SELECT communication_log, communication_log::text AS t FROM grievances WHERE id = %s", (gid,))
        row = cur.fetchone()
    assert row["communication_log"][-1]["by"] == "PRINCIPAL"
    assert pid not in row["t"]


# ---- Task 7: remaining services, exports and delivery ------------------------------


@needs_db
def test_export_job_writes_masked_principal_ids(tx, tmp_path, monkeypatch):
    import csv
    import dataclasses

    from dpdpcms_py import jobs, pii
    from dpdpcms_py.config import settings
    from dpdpcms_py.services.compliance import GrievanceService
    from dpdpcms_py.services.governance import JobService

    pid = "asha@example.org"
    monkeypatch.setattr(jobs, "settings", dataclasses.replace(settings, export_path=tmp_path))
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
    _grant(fid, pol, pid)
    GrievanceService().submit_grievance(
        _api_ctx(fid, {"user_id": pid, "type": "GENERAL_COMPLAINT", "subject": "s", "description": "d"})
    )
    for subtype in ("CONSENT", "PRINCIPAL", "GRIEVANCE"):
        JobService().create_job(_ctx(fid, {"job_type": "EXPORT", "subtype": subtype}, operator_id="op-1"))
    assert jobs.execute_queued_jobs()["completed"] >= 3
    with tx.cursor() as cur:
        cur.execute("SELECT subtype, output_file_path FROM jobs WHERE fiduciary_id = %s", (fid,))
        paths = {r["subtype"]: r["output_file_path"] for r in cur.fetchall()}
    assert set(paths) == {"CONSENT", "PRINCIPAL", "GRIEVANCE"}
    for subtype, path in paths.items():
        text = open(path, encoding="utf-8").read()
        assert pid not in text, f"plaintext principal id in the {subtype} export"
        rows = list(csv.DictReader(text.splitlines()))
        assert rows and {r["user_id"] for r in rows} == {pii.mask(pid)}, subtype


@needs_db
def test_job_input_payload_has_no_raw_principal_id(tx):
    import json

    from dpdpcms_py import pii
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.governance import JobService

    pid = "asha@example.org"
    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    service = JobService()
    as_dict = {"user_id": pid, "filters": [{"principal_id": f" {pid} "}], "purpose_id": "care"}
    ids = [
        service.create_job(_ctx(fid, {"job_type": "EXPORT", "input_payload": raw}, operator_id="op-1"))["job_id"]
        for raw in (as_dict, json.dumps(as_dict))
    ]
    with tx.cursor() as cur:
        cur.execute("SELECT input_payload FROM jobs WHERE id = ANY(%s::uuid[])", (ids,))
        stored = [r["input_payload"] for r in cur.fetchall()]
    assert len(stored) == 2
    for text in stored:
        assert pid not in text
        assert json.loads(text) == {
            "user_id_hmac": pii.hmac_hex(pid),
            "filters": [{"principal_id_hmac": pii.hmac_hex(pid)}],
            "purpose_id": "care",
        }
    with pytest.raises(ApiError) as err:
        service.create_job(_ctx(fid, {"job_type": "EXPORT", "input_payload": f"user {pid}"}, operator_id="op-1"))
    assert err.value.status == 400


@needs_db
def test_notification_delivery_decrypts_recipient(tx, monkeypatch):
    import dataclasses

    from dpdpcms_py import delivery, pii
    from dpdpcms_py.config import settings

    pid = "+919876543210"
    sent = []
    monkeypatch.setattr(delivery, "settings", dataclasses.replace(settings, sms_gateway_url="https://sms.example"))
    monkeypatch.setattr(delivery, "post_json", lambda url, body, timeout=0: sent.append(body) or (200, "ok"))
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        enc, h = _enc_hmac(cur, pid)
        cur.execute(
            "INSERT INTO notifications (recipient_type, recipient_id_enc, recipient_id_hmac, fiduciary_id,"
            " notification_type) VALUES ('PRINCIPAL', %s, %s, %s, 'CONSENT_RECORDED') RETURNING id",
            (enc, h, fid),
        )
        nid = cur.fetchone()["id"]
    delivery.process_pending_notifications()
    # Other committed notifications may be pending too; this one reaches the
    # gateway once, under its decrypted id.
    assert [b["recipient_id"] for b in sent].count(pid) == 1
    with tx.cursor() as cur:
        cur.execute(
            "SELECT channel, status, recipient_hmac, to_jsonb(d)::text AS j FROM notification_deliveries d"
            " WHERE notification_id = %s",
            (nid,),
        )
        rows = cur.fetchall()
    assert {(r["channel"], r["status"]) for r in rows} == {("IN_APP", "SENT"), ("SMS", "SENT")}
    assert all(r["recipient_hmac"] == pii.hmac_hex(pid) and pid not in r["j"] for r in rows)


@needs_db
def test_consent_history_pdf_masks_the_principal_for_operators_only(tx, monkeypatch):
    from dpdpcms_py import pdfgen, pii
    from dpdpcms_py.services.consent import ConsentService

    pid = "asha@example.org"
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
    _grant(fid, pol, pid)
    captured = []
    monkeypatch.setattr(pdfgen, "text_pdf", lambda title, lines: captured.append(lines) or b"%PDF")
    service = ConsentService()
    service.export_consent_history(_ctx(fid, {"user_id": pid, "format": "pdf"}, operator_id="op-1"))
    service.export_consent_history(
        _ctx(fid, {"user_id": pid, "format": "pdf"}, auth_via_principal_jwt=True, principal_user_id=pid)
    )
    service.export_consent_history(_api_ctx(fid, {"user_id": pid, "format": "pdf"}))
    assert [lines[0] for lines in captured] == [
        f"Principal: {pii.mask(pid)}",
        f"Principal: {pid}",
        f"Principal: {pid}",
    ]
    assert pid not in "\n".join(captured[0])


@needs_db
def test_alerts_store_encrypted_recipient_and_acknowledger(tx):
    from dpdpcms_py import pii
    from dpdpcms_py.context import RequestContext
    from dpdpcms_py.services.alerts import AlertService

    pid = "asha@example.org"
    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    service = AlertService()
    alert_id = service.notify_alert(
        _api_ctx(fid, {"recipient_type": "PRINCIPAL", "recipient_id": pid, "alert_type": "CONSENT_EXPIRING"})
    )["alert_id"]
    principal = RequestContext(
        path="/api/v1/client/alerts",
        category="client",
        service="alerts",
        payload={},
        headers={},
        fiduciary_id=fid,
        principal_user_id=f" {pid} ",
        auth_via_principal_jwt=True,
    )
    assert [a["recipient_id"] for a in service.list_alerts(principal)] == [pid]
    principal.payload = {"alert_id": alert_id}
    assert service.acknowledge_alert(principal)["status"] == "ACKNOWLEDGED"
    [row] = service.list_alerts(_ctx(fid, {}, operator_id="op-1"))
    assert (row["recipient_id"], row["acknowledged_by"]) == (pii.mask(pid), pii.mask(pid))
    assert not any(k.endswith(("_enc", "_hmac")) for k in row)
    with tx.cursor() as cur:
        _no_plaintext(cur, fid, pid, ("alerts",))
        cur.execute("SELECT recipient_id_hmac, acknowledged_by_hmac FROM alerts WHERE id = %s", (alert_id,))
        assert set(cur.fetchone().values()) == {pii.hmac_hex(pid)}


# ---- Task 7 fix round 1 -------------------------------------------------------------


def test_hmac_principal_keys_fails_closed_on_nested_values():
    import json

    from dpdpcms_py import pii

    pid = "asha@example.org"
    nested = {"email": pid, "phone": "+919876543210"}
    out = pii.hmac_principal_keys({"user_id": nested, "recipient_id": [pid], "guardian_id": True, "k": {"a": 1}})
    assert pid not in json.dumps(out)
    assert out["user_id_hmac"] == pii.hmac_hex(json.dumps(nested, sort_keys=True, ensure_ascii=False))
    assert out["recipient_id_hmac"] == pii.hmac_hex(json.dumps([pid], sort_keys=True, ensure_ascii=False))
    assert out["guardian_id_hmac"] == pii.hmac_hex("true") and out["k"] == {"a": 1}


def test_mask_principal_keys_masks_scalars_and_nested_values():
    import json

    from dpdpcms_py import pii

    pid = "asha@example.org"
    value = {"user_id": pid, "purpose_ids": ["care"], "items": [{"principal_id": pid}], "nominee_id": {"e": pid}}
    out = pii.mask_principal_keys(value)
    assert pid not in json.dumps(out)
    assert out["user_id"] == pii.mask(pid) and out["items"][0]["principal_id"] == pii.mask(pid)
    assert out["purpose_ids"] == ["care"] and out["nominee_id"] == "***"
    assert value["user_id"] == pid, "the input is not mutated"


def test_record_alert_failure_logs_no_row_detail(monkeypatch, caplog):
    import logging

    import psycopg
    from dpdpcms_py.services import lifecycle

    pid = "asha@example.org"

    def failing_insert(sql, params=()):
        raise psycopg.errors.NotNullViolation(f"null value in column; Failing row contains ({pid}, x)")

    monkeypatch.setattr(lifecycle.db, "insert_returning", failing_insert)
    with caplog.at_level(logging.DEBUG, logger="dpdpcms.lifecycle"):
        assert lifecycle.record_alert(FID, "CONSENT_WITHDRAWN", None, {"user_id": pid}) is None
    assert caplog.records, "the failure is still logged"
    assert pid not in caplog.text
    assert "NotNullViolation" in caplog.text and "23502" in caplog.text


@needs_db
def test_operator_alert_payloads_mask_principal_ids(tx):
    import json

    from dpdpcms_py.services.alerts import AlertService
    from dpdpcms_py.services.consent import ConsentService

    pid = "asha@example.org"
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
    _grant(fid, pol, pid)
    ConsentService().withdraw_consent(_api_ctx(fid, {"user_id": pid, "purpose_ids": ["care"]}))
    service = AlertService()
    as_operator = service.list_alerts(_ctx(fid, {}, operator_id="op-1"))
    assert {a["alert_type"] for a in as_operator} >= {"CONSENT_GIVEN", "CONSENT_WITHDRAWN"}
    assert pid not in json.dumps(as_operator, default=str)
    as_key = service.list_alerts(_api_ctx(fid, {}))
    assert {a["payload"]["user_id"] for a in as_key} == {pid}


@needs_db
def test_certificate_signs_the_principal_hmac_and_survives_erasure(tx):
    from dpdpcms_py import pii
    from dpdpcms_py.services import governance
    from dpdpcms_py.services.compliance import erase_cms_copy
    from tests.test_integration_db import _log

    pid = "asha@example.org"
    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        for i in range(2):
            _log(fid, pid, f"E{i}")
    service = governance.LegalService()
    cert_id = service.generate_certificate(
        _ctx(fid, {"fiduciary_id": fid, "subject_principal_id": pid, "case_ref_id": "c1"})
    )["certificate_id"]
    with tx.cursor() as cur:
        cur.execute("SELECT certificate_data FROM evidence_certificates WHERE id = %s", (cert_id,))
        data = cur.fetchone()["certificate_data"]
    assert "principal_id" not in data and data["principal_id_hmac"] == pii.hmac_hex(pid)
    assert service.verify_certificate(_ctx(fid, {"id": cert_id}))["valid"] is True
    shown = service.get_certificate(_ctx(fid, {"id": cert_id}, operator_id="op-1"))
    assert shown["subject_principal_id"] == pii.mask(pid) and "principal_id" not in shown["data"]
    assert service.get_certificate(_api_ctx(fid, {"id": cert_id}))["subject_principal_id"] == pid

    erase_cms_copy(fid, pid)
    with tx.cursor() as cur:
        cur.execute("SELECT to_jsonb(c)::text AS j FROM evidence_certificates c WHERE id = %s", (cert_id,))
        row = cur.fetchone()["j"]
    assert pid not in row
    # Ruling O: an erased subject is not tampering - the integrity checks still
    # run and pass, and the result says the subject was erased (no principal id).
    result = service.verify_certificate(_ctx(fid, {"id": cert_id}))
    assert result["valid"] is True and result["subject_erased"] is True
    assert pid not in str(result) and "erased:" not in str(result)


@needs_db
def test_erased_subject_certificate_still_fails_when_tampered(tx):
    from dpdpcms_py import audit
    from dpdpcms_py.services import governance
    from dpdpcms_py.services.compliance import erase_cms_copy
    from tests.test_integration_db import _log, real_db

    pid = "asha@example.org"
    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        for i in range(3):
            _log(fid, pid, f"E{i}")
    service = governance.LegalService()
    cert_id = service.generate_certificate(_ctx(fid, {"fiduciary_id": fid, "subject_principal_id": pid}))[
        "certificate_id"
    ]
    erase_cms_copy(fid, pid)
    with tx.cursor() as cur:
        cur.execute("SELECT certificate_data FROM evidence_certificates WHERE id = %s", (cert_id,))
        data = cur.fetchone()["certificate_data"]
        # Altered without re-signing: the signature check fails.
        cur.execute(
            "UPDATE evidence_certificates SET certificate_data = %s WHERE id = %s",
            (real_db.as_jsonb({**data, "case_ref_id": "forged"}), cert_id),
        )
    result = service.verify_certificate(_ctx(fid, {"id": cert_id}))
    assert result["valid"] is False and "altered" in result["reason"]
    # Re-signed but naming a hash that is not in the ledger: the trail check fails.
    forged = {**data, "evidence_trail": [{**data["evidence_trail"][0], "hash": "0" * 64}, *data["evidence_trail"][1:]]}
    forged["signature"] = audit.certificate_signature(forged)
    with tx.cursor() as cur:
        cur.execute(
            "UPDATE evidence_certificates SET certificate_data = %s WHERE id = %s", (real_db.as_jsonb(forged), cert_id)
        )
    result = service.verify_certificate(_ctx(fid, {"id": cert_id}))
    assert result["valid"] is False and "no longer present" in result["reason"]


# ---- Task 8: guardian evidence, consent IP and audit details --------------------------


def _decrypt(cur, value):
    from dpdpcms_py import pii
    from dpdpcms_py.config import settings

    cur.execute(f"SELECT {pii.dec_sql('%s::text')} AS v", (value, settings.db_encryption_key))
    return cur.fetchone()["v"]


@needs_db
def test_consent_ip_and_guardian_evidence_stored_encrypted(tx):
    import dataclasses
    import json

    from dpdpcms_py.services.consent import ConsentService

    ip, ref, claimed = "203.0.113.77", "DL-REF-998877", "192.0.2.55"
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        assert "ip_address" not in _columns(cur, "consent_records")
        assert {"verification_ref_id", "proof_metadata"}.isdisjoint(_columns(cur, "parental_verification_logs"))
    service = ConsentService()
    consent_ctx = dataclasses.replace(
        _api_ctx(
            fid,
            {
                "user_id": "asha",
                "policy_id": pol,
                "data_point_consents": [{"id": "care", "consent_granted": True}],
                "ip_address": claimed,
                "consent_mechanism": "PAPER_FORM",
            },
        ),
        source_ip=ip,
    )
    service.record_consent(consent_ctx)
    guardian_ctx = _api_ctx(
        fid,
        {
            "child_principal_id": "kid-1",
            "guardian_principal_id": "asha",
            "verification_mechanism": "AADHAAR_VC",
            "verification_ref_id": ref,
            "proof_metadata": {"vc_hash": "abc123"},
        },
    )
    log_id = service.record_parent_consent(guardian_ctx)["verification_log_id"]

    with tx.cursor() as cur:
        cur.execute(
            "SELECT ip_address_enc, client_metadata, to_jsonb(c)::text AS j FROM consent_records c"
            " WHERE fiduciary_id = %s",
            (fid,),
        )
        row = cur.fetchone()
        assert ip not in row["j"] and claimed not in row["j"]
        assert _decrypt(cur, row["ip_address_enc"]) == ip
        # The claimed IP is kept apart, encrypted; the other claims as sent.
        meta = row["client_metadata"]
        assert "ip_address" not in meta and meta["consent_mechanism"] == "PAPER_FORM"
        assert _decrypt(cur, meta["ip_address_enc"]) == claimed
        cur.execute(
            "SELECT verification_ref_id_enc, proof_metadata_enc, to_jsonb(p)::text AS j"
            " FROM parental_verification_logs p WHERE id = %s",
            (log_id,),
        )
        row = cur.fetchone()
        assert ref not in row["j"] and "abc123" not in row["j"]
        assert _decrypt(cur, row["verification_ref_id_enc"]) == ref
        proof = json.loads(_decrypt(cur, row["proof_metadata_enc"]))
        assert proof["vc_hash"] == "abc123" and "verification_detail" in proof


def _record(fid, pol, user, ip, claimed=None):
    import dataclasses

    from dpdpcms_py.services.consent import ConsentService

    payload = {"user_id": user, "policy_id": pol, "data_point_consents": [{"id": "care", "consent_granted": True}]}
    if claimed:
        payload["ip_address"] = claimed
    ConsentService().record_consent(dataclasses.replace(_api_ctx(fid, payload), source_ip=ip))


@needs_db
def test_consent_reads_never_return_ip_ciphertext(tx):
    """Ruling S: no read returns ip_address_enc; an API-key caller sees the
    session and claimed IPs, a console operator gets null for both."""
    import dataclasses

    from dpdpcms_py.services.consent import ConsentService

    ip, claimed = "203.0.113.78", "192.0.2.56"
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
    _record(fid, pol, "asha", ip, claimed)
    _record(fid, pol, "ramesh", ip)
    service = ConsentService()

    def reads(ctx, user):
        active = service.get_active_consent(dataclasses.replace(ctx, payload={"user_id": user}))
        details = service.get_consent_record_details(dataclasses.replace(ctx, payload={"record_id": active["id"]}))
        history = service.list_consent_history(dataclasses.replace(ctx, payload={"user_id": user}))
        return [active, *active["active_records"], details, *history]

    for row in reads(_api_ctx(fid, {}), "asha"):
        assert "ip_address_enc" not in row and "claimed_ip_address" not in row
        assert row["ip_address"] == ip
        assert row["client_metadata"] == {"ip_address": claimed}
    for row in reads(_api_ctx(fid, {}), "ramesh"):
        assert row["ip_address"] == ip and row["client_metadata"] == {}
    for row in reads(_ctx(fid, {}, operator_id="op-1"), "asha"):
        assert "ip_address_enc" not in row and "claimed_ip_address" not in row
        assert row["ip_address"] is None
        assert row["client_metadata"] == {"ip_address": None}


@needs_db
def test_audit_details_pseudonymise_principal_keys(tx):
    import json

    from dpdpcms_py import audit, pii
    from dpdpcms_py.security import pseudonym

    assert pii.PRINCIPAL_KEYS <= audit.PRINCIPAL_DETAIL_KEYS
    details = {
        "user_id": " asha@example.org ",
        "policy_id": "pol-1",
        "nested": {"guardian_id": "g-1", "items": [{"nominee_id": "n-1"}, {"recipient_id": "r-1", "note": "keep"}]},
        "child_principal_id": "kid-1",
        "subject_principal_id": "subj-1",
        "principal_id": None,
    }
    audit.log_event("asha@example.org", None, "SYSTEM", None, "T8_DETAILS", details)
    audit.log_event(None, None, "SYSTEM", None, "T8_STRING", "user_id=raw-string")
    with tx.cursor() as cur:
        cur.execute(
            "SELECT audit_action, context_details FROM audit_logs WHERE audit_action IN ('T8_DETAILS', 'T8_STRING')"
        )
        stored = {r["audit_action"]: r["context_details"] for r in cur.fetchall()}
    assert stored["T8_STRING"] == "user_id=raw-string"
    for raw in ("asha@example.org", "g-1", "n-1", "r-1", "kid-1", "subj-1"):
        assert raw not in stored["T8_DETAILS"]
    got = json.loads(stored["T8_DETAILS"])
    assert got["user_id"] == pseudonym("asha@example.org")
    assert got["policy_id"] == "pol-1" and got["principal_id"] is None
    assert got["nested"]["guardian_id"] == pseudonym("g-1")
    assert got["nested"]["items"] == [
        {"nominee_id": pseudonym("n-1")},
        {"recipient_id": pseudonym("r-1"), "note": "keep"},
    ]
    assert got["child_principal_id"] == pseudonym("kid-1")
    assert got["subject_principal_id"] == pseudonym("subj-1")
    # The caller's dict is not modified.
    assert details["user_id"] == " asha@example.org "


@needs_db
def test_audit_user_pseudonym_ignores_surrounding_spaces(tx):
    from dpdpcms_py import audit

    audit.log_event(" a ", None, "SYSTEM", None, "T8_PAD", {})
    audit.log_event("a", None, "SYSTEM", None, "T8_PAD", {})
    audit.log_event("A", None, "SYSTEM", None, "T8_PAD", {})
    with tx.cursor() as cur:
        cur.execute("SELECT user_id FROM audit_logs WHERE audit_action = 'T8_PAD' ORDER BY timestamp")
        padded, plain, upper = (r["user_id"] for r in cur.fetchall())
    assert padded == plain != upper
    assert len(audit.list_logs({"user_id": " a", "audit_action": "T8_PAD"})) == 2


@needs_db
def test_audit_source_ip_encrypted_and_chain_verifies(tx, monkeypatch):
    from datetime import UTC, datetime

    from dpdpcms_py import audit
    from dpdpcms_py.config import settings

    ip = "198.51.100.23"
    with tx.cursor() as cur:
        year = _live_partition_years(cur)[0]
    for day in (1, 2):
        monkeypatch.setattr(audit, "_now", lambda d=day: datetime(year, 3, d, tzinfo=UTC))
        audit.log_event("asha", None, "SYSTEM", None, "T8_IP", {}, source_ip=ip)
    with tx.cursor() as cur:
        cur.execute("SELECT source_ip FROM audit_logs WHERE audit_action = 'T8_IP'")
        stored = [r["source_ip"] for r in cur.fetchall()]
        assert len(stored) == 2 and ip not in stored
        assert {_decrypt(cur, s) for s in stored} == {ip}
    assert audit.verify_chain()["intact"] is True
    # The console reads show the readable IP; a pre-db/35 plaintext value reads back as stored.
    logs = audit.list_logs({"audit_action": "T8_IP"})
    assert [r["source_ip"] for r in logs] == [ip, ip]
    assert audit.get_log(logs[0]["id"])["source_ip"] == ip
    with tx.cursor() as cur:
        cur.execute("SELECT tsi_audit_source_ip('10.0.0.9', %s) AS v", (settings.db_encryption_key,))
        assert cur.fetchone()["v"] == "10.0.0.9"

    # The archived year keeps the ciphertext and still verifies; source_ip is
    # TEXT on the parent, every partition and every archive table.
    _archive_everything(monkeypatch)
    monkeypatch.setattr(audit, "_now", lambda: datetime(2200, 6, 1, tzinfo=UTC))
    audit.log_event("asha", None, "SYSTEM", None, "T8_IP", {}, source_ip=ip)
    chain = audit.verify_chain()
    assert chain["intact"] is True and chain["rows_checked"] >= 3
    with tx.cursor() as cur:
        cur.execute(
            "SELECT table_name, data_type FROM information_schema.columns"
            " WHERE table_schema = 'public' AND column_name = 'source_ip' AND table_name LIKE 'audit_logs%%'"
            " AND table_name <> 'audit_logs_legacy_pre32'"
        )
        types = {r["table_name"]: r["data_type"] for r in cur.fetchall()}
    assert f"audit_logs_y{year}_archive" in types and "audit_logs" in types
    assert set(types.values()) == {"text"}, types


@needs_db
def test_audit_source_ip_reader_keeps_legacy_plaintext_and_raises_on_wrong_key(tx):
    import psycopg
    from dpdpcms_py.config import settings

    key = settings.db_encryption_key
    with tx.cursor() as cur:
        for legacy in ("10.0.0.9", "2001:db8::1", "::1"):
            cur.execute("SELECT tsi_audit_source_ip(%s, %s) AS v", (legacy, key))
            assert cur.fetchone()["v"] == legacy
        cur.execute("SELECT tsi_audit_source_ip(NULL, %s) AS v", (key,))
        assert cur.fetchone()["v"] is None
        cur.execute("SELECT encode(pgp_sym_encrypt('198.51.100.9', %s), 'base64') AS c", (key,))
        cipher = cur.fetchone()["c"]
        cur.execute("SELECT tsi_audit_source_ip(%s, %s) AS v", (cipher, key))
        assert cur.fetchone()["v"] == "198.51.100.9"
        with pytest.raises(psycopg.Error, match="Wrong key or corrupt data"), tx.transaction():
            cur.execute("SELECT tsi_audit_source_ip(%s, %s) AS v", (cipher, key + "-wrong"))


@needs_db
def test_erasure_scrubs_encrypted_ip(tx):
    from dpdpcms_py import pii
    from dpdpcms_py.config import settings
    from dpdpcms_py.services.compliance import erase_cms_copy
    from tests.test_integration_db import _seed_consent

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha", ip="9.9.9.9", user_agent="curl/8")
        _seed_consent(cur, fid, pol, "ramesh", ip="1.2.3.5")
    # Recorded through the API with a claimed IP (client_metadata.ip_address_enc).
    _record(fid, pol, "asha", "9.9.9.8", claimed="8.8.4.4")
    _record(fid, pol, "ramesh", "1.2.3.5", claimed="8.8.8.8")
    counts = erase_cms_copy(fid, "asha")
    assert counts["consent_records.metadata"] == 2
    key = settings.db_encryption_key
    claimed_sql = pii.dec_sql("client_metadata->>'ip_address_enc'")
    with tx.cursor() as cur:
        cur.execute(
            f"SELECT {pii.dec_sql('user_id_enc')} AS u, {pii.dec_sql('ip_address_enc')} AS ip, user_agent,"
            f" {claimed_sql} AS claimed, client_metadata"
            " FROM consent_records WHERE fiduciary_id = %s",
            (key, key, key, fid),
        )
        rows = {}
        for r in cur.fetchall():
            rows.setdefault(r["u"], []).append(r)
    erased = next(u for u in rows if u.startswith("erased:"))
    assert len(rows[erased]) == 2
    for row in rows[erased]:
        assert row["ip"] == "0.0.0.0" and row["user_agent"] is None
        assert row["claimed"] in (None, "0.0.0.0")
    # The API-recorded record had a claimed IP: it is the encrypted 0.0.0.0 now;
    # the seeded one had none and still has none.
    assert sorted(str(r["claimed"]) for r in rows[erased]) == ["0.0.0.0", "None"]
    assert "8.8.4.4" not in str([r["client_metadata"] for r in rows[erased]])
    ramesh = {(r["ip"], r["claimed"]) for r in rows["ramesh"]}
    assert ramesh == {("1.2.3.5", None), ("1.2.3.5", "8.8.8.8")}
    # A second erasure does not trip the append-only trigger.
    assert erase_cms_copy(fid, "asha")["consent_records.metadata"] == 0


# ---- Task 9: audited, rate-limited reveal_user_id --------------------------------------


def _reveal_operator(cur, fid, role, name):
    """An ACTIVE operator whose email_hmac matches what authenticate() looks up."""
    from dpdpcms_py import db

    email = f"{name}-{uuid.uuid4().hex[:8]}@example.org"
    cur.execute(
        "INSERT INTO operators (name, email_plaintext, role, fiduciary_id, email_enc, email_hmac)"
        f" VALUES (%s, %s, %s, %s, 'x', {db.hmac_expr()}) RETURNING id",
        (name, email, role, fid, *db.bind_hmac(email)),
    )
    return str(cur.fetchone()["id"]), email


def _bearer(email, role):
    from dpdpcms_py import security

    return {"Authorization": f"Bearer {security.token(email, 'n', role)}"}


def _reveal(headers, payload, category="admin", method="post"):
    from dpdpcms_py import main
    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    body = {"_func": "reveal_user_id", **payload}
    if method == "get":
        return client.get(f"/api/v1/{category}/pii", params=body, headers=headers)
    return client.post(f"/api/v1/{category}/pii", json=body, headers=headers)


def _reveal_rows(cur, initiator=None):
    sql = "SELECT * FROM audit_logs WHERE audit_action = 'PII_REVEALED'"
    params = ()
    if initiator:
        sql += " AND initiator = %s"
        params = (initiator,)
    cur.execute(sql + " ORDER BY timestamp", params)
    return cur.fetchall()


def _seed_revealable(cur, fid, pol):
    """One row of every revealable source for principal 'asha' in tenant `fid`."""
    from dpdpcms_py.services.consent import ConsentService

    _record(fid, pol, "asha", "203.0.113.90")
    cur.execute("SELECT id FROM consent_records WHERE fiduciary_id = %s", (fid,))
    consent_id = str(cur.fetchone()["id"])
    enc, hmac = _pid(cur, "asha")
    cur.execute(
        "INSERT INTO grievances (user_id_enc, user_id_hmac, fiduciary_id, type, subject, description,"
        " reference_number) VALUES (%s, %s, %s, 'GENERAL_COMPLAINT', 's', 'd', %s) RETURNING id",
        (enc, hmac, fid, f"GRV-2026-{fid[:6].upper()}"),
    )
    grievance_id = str(cur.fetchone()["id"])
    cur.execute(
        "INSERT INTO purge_requests (user_id_enc, user_id_hmac, fiduciary_id, purpose_id, trigger_event)"
        " VALUES (%s, %s, %s, 'care', 'ERASURE_REQUEST') RETURNING id",
        (enc, hmac, fid),
    )
    purge_id = str(cur.fetchone()["id"])
    cur.execute(
        "INSERT INTO data_principal (fiduciary_id, user_id_enc, user_id_hmac) VALUES (%s, %s, %s)"
        " ON CONFLICT DO NOTHING",
        (fid, enc, hmac),
    )
    log_id = ConsentService().record_parent_consent(
        _api_ctx(
            fid,
            {
                "child_principal_id": "kid-9",
                "guardian_principal_id": "asha",
                "verification_mechanism": "AADHAAR_VC",
                "verification_ref_id": "DL-REF-4242",
                "proof_metadata": {"vc_hash": "feed42"},
            },
        )
    )["verification_log_id"]
    return {
        "consent_record": consent_id,
        "grievance": grievance_id,
        "purge_request": purge_id,
        "data_principal": hmac,
        "parental_verification": str(log_id),
    }


def _source_payload(fid, source, ref):
    key = "user_ref" if source == "data_principal" else "id"
    return {"source": source, "fiduciary_id": fid, key: ref}


@needs_db
def test_dpo_reveals_own_tenant_and_audit_row_precedes_response(tx, monkeypatch):
    import json

    from dpdpcms_py import main, security
    from dpdpcms_py.services import pii as pii_service

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        refs = _seed_revealable(cur, fid, pol)
        dpo, email = _reveal_operator(cur, fid, "DPO", "dee")
    headers = _bearer(email, "DPO")

    response = _reveal(headers, _source_payload(fid, "consent_record", refs["consent_record"]))
    assert response.status_code == 200, response.text
    assert response.json() == {
        "source": "consent_record",
        "id": refs["consent_record"],
        "fields": {"user_id": "asha", "ip_address": "203.0.113.90"},
    }
    with tx.cursor() as cur:
        rows = _reveal_rows(cur, f"OPERATOR:{dpo}")
    assert len(rows) == 1
    row = rows[0]
    assert (str(row["fiduciary_id"]), row["service_type"]) == (fid, "DPO_CONSOLE")
    assert row["user_id"] == security.pseudonym("asha")
    assert json.loads(row["context_details"]) == {
        "source": "consent_record",
        "record_id": refs["consent_record"],
        "fields": ["user_id", "ip_address"],
    }
    assert "asha" not in row["context_details"] and "203.0.113.90" not in row["context_details"]

    # Every whitelisted source reveals exactly its own fields.
    expected = {
        "grievance": {"user_id": "asha"},
        "purge_request": {"user_id": "asha"},
        "data_principal": {"user_id": "asha"},
        "parental_verification": {"guardian_id": "asha", "verification_ref_id": "DL-REF-4242"},
    }
    for source, fields in expected.items():
        response = _reveal(headers, _source_payload(fid, source, refs[source]))
        assert response.status_code == 200, (source, response.text)
        body = response.json()
        assert (body["source"], body["id"]) == (source, refs[source])
        if source == "parental_verification":
            assert body["fields"].pop("proof_metadata")["vc_hash"] == "feed42"
        assert body["fields"] == fields
    with tx.cursor() as cur:
        rows = _reveal_rows(cur, f"OPERATOR:{dpo}")
    assert len(rows) == 5
    # The guardian reveal is traced to the child principal, not the guardian.
    assert rows[-1]["user_id"] == security.pseudonym("kid-9")

    # The audit row is written (and committed) before the response is built:
    # a failure serialising the response still leaves the row in place.
    def broken_response(*args, **kwargs):
        raise RuntimeError("serialisation failed")

    with monkeypatch.context() as patch:
        patch.setattr(main, "_json_response", broken_response)
        response = _reveal(headers, _source_payload(fid, "grievance", refs["grievance"]))
    assert response.status_code == 500 and "asha" not in response.text
    with tx.cursor() as cur:
        assert len(_reveal_rows(cur, f"OPERATOR:{dpo}")) == 6

    # No audit row, no plaintext.
    def failing_log(*args, **kwargs):
        raise RuntimeError("audit down")

    with monkeypatch.context() as patch:
        patch.setattr(pii_service, "log_event", failing_log)
        response = _reveal(headers, _source_payload(fid, "grievance", refs["grievance"]))
    assert response.status_code == 500 and "asha" not in response.text


@needs_db
def test_admin_reveals_any_tenant(tx):
    with tx.cursor() as cur:
        fid_a, pol_a = _seed_tenant(cur)
        fid_b, pol_b = _seed_tenant(cur)
        refs_a = _seed_revealable(cur, fid_a, pol_a)
        refs_b = _seed_revealable(cur, fid_b, pol_b)
        admin, email = _reveal_operator(cur, None, "ADMIN", "root")
    headers = _bearer(email, "ADMIN")
    for fid, refs in ((fid_a, refs_a), (fid_b, refs_b)):
        response = _reveal(headers, _source_payload(fid, "grievance", refs["grievance"]))
        assert response.status_code == 200, response.text
        assert response.json()["fields"] == {"user_id": "asha"}
    # The record must belong to the named tenant.
    response = _reveal(headers, _source_payload(fid_a, "grievance", refs_b["grievance"]))
    assert response.status_code == 404
    with tx.cursor() as cur:
        rows = _reveal_rows(cur, f"OPERATOR:{admin}")
    assert sorted(str(r["fiduciary_id"]) for r in rows) == sorted([fid_a, fid_b])


@needs_db
def test_operator_auditor_api_key_principal_get_403_and_no_audit_row(tx):
    from dpdpcms_py import security

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        refs = _seed_revealable(cur, fid, pol)
        _, op_email = _reveal_operator(cur, fid, "OPERATOR", "opi")
        _, auditor_email = _reveal_operator(cur, fid, "AUDITOR", "aud")
        # A custom tenant role granted pii:reveal is still neither DPO nor ADMIN.
        cur.execute(
            "INSERT INTO roles (code, name, permissions, fiduciary_id) VALUES ('REVEALER', 'r', %s, %s)",
            ('["pii:reveal"]', fid),
        )
        _, custom_email = _reveal_operator(cur, fid, "REVEALER", "rev")
        _, dpo_email = _reveal_operator(cur, fid, "DPO", "dee")
    payload = _source_payload(fid, "consent_record", refs["consent_record"])
    for email, role in ((op_email, "OPERATOR"), (auditor_email, "AUDITOR")):
        for method in ("post", "get"):
            response = _reveal(_bearer(email, role), payload, method=method)
            assert response.status_code == 403, (role, method, response.text)
            assert "asha" not in response.text
    response = _reveal(_bearer(custom_email, "REVEALER"), payload)
    assert response.status_code == 403 and "asha" not in response.text
    # API keys and principal tokens never reach it: the client category refuses
    # the function, and the admin category refuses a principal token.
    principal = {"Authorization": f"Bearer {security.principal_token(fid, 'asha')}"}
    api_key = {"X-API-Key": "k", "X-API-Secret": "s"}
    for headers in (principal, api_key):
        for method in ("post", "get"):
            response = _reveal(headers, payload, category="client", method=method)
            assert response.status_code == 403, response.text
        assert _reveal(headers, payload).status_code == 401
    # Not a read: a DPO cannot reveal over GET either.
    assert _reveal(_bearer(dpo_email, "DPO"), payload, method="get").status_code == 405
    with tx.cursor() as cur:
        assert _reveal_rows(cur) == []


@needs_db
def test_dpo_other_tenant_403(tx):
    with tx.cursor() as cur:
        fid_a, _ = _seed_tenant(cur)
        fid_b, pol_b = _seed_tenant(cur)
        refs_b = _seed_revealable(cur, fid_b, pol_b)
        _, email = _reveal_operator(cur, fid_a, "DPO", "dee")
    headers = _bearer(email, "DPO")
    response = _reveal(headers, _source_payload(fid_b, "grievance", refs_b["grievance"]))
    assert response.status_code == 403, response.text
    assert "asha" not in response.text
    # Naming its own tenant does not reach another tenant's record either.
    response = _reveal(headers, _source_payload(fid_a, "grievance", refs_b["grievance"]))
    assert response.status_code == 404
    with tx.cursor() as cur:
        assert _reveal_rows(cur) == []


@needs_db
def test_21st_reveal_in_a_minute_is_429(tx, monkeypatch):
    from datetime import timedelta

    from dpdpcms_py import audit

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        refs = _seed_revealable(cur, fid, pol)
        dpo, email = _reveal_operator(cur, fid, "DPO", "dee")
        _, other_email = _reveal_operator(cur, fid, "DPO", "dan")
    headers = _bearer(email, "DPO")
    payload = _source_payload(fid, "grievance", refs["grievance"])
    for _ in range(20):
        assert _reveal(headers, payload).status_code == 200
    response = _reveal(headers, payload)
    assert response.status_code == 429, response.text
    assert "asha" not in response.text
    with tx.cursor() as cur:
        assert len(_reveal_rows(cur, f"OPERATOR:{dpo}")) == 20
    # The limit is per operator...
    assert _reveal(_bearer(other_email, "DPO"), payload).status_code == 200
    # ...over a rolling 60 s: a minute later the operator may reveal again.
    real_now = audit._now
    monkeypatch.setattr(audit, "_now", lambda: real_now() + timedelta(seconds=61))
    assert _reveal(headers, payload).status_code == 200


@needs_db
def test_unknown_source_400(tx):
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.pii import PiiService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_revealable(cur, fid, pol)
        _, email = _reveal_operator(cur, fid, "DPO", "dee")
    headers = _bearer(email, "DPO")
    for payload in (
        {"source": "operators", "fiduciary_id": fid, "id": str(uuid.uuid4())},
        {"source": "consent_records; DROP TABLE x", "fiduciary_id": fid, "id": str(uuid.uuid4())},
        {"source": "grievance", "fiduciary_id": fid},
        {"source": "data_principal", "fiduciary_id": fid},
        {"source": "grievance", "fiduciary_id": fid, "id": "not-a-uuid"},
    ):
        response = _reveal(headers, payload)
        assert response.status_code == 400, (payload, response.text)
    # The service itself refuses a source outside its whitelist.
    ctx = _ctx_as_operator(fid, "DPO", {"_func": "reveal_user_id", "source": "operators", "id": str(uuid.uuid4())})
    with pytest.raises(ApiError) as exc:
        PiiService().reveal_user_id(ctx)
    assert exc.value.status == 400
    with tx.cursor() as cur:
        assert _reveal_rows(cur) == []


def _ctx_as_operator(fid, role, payload):
    from dpdpcms_py.context import RequestContext

    return RequestContext(
        path="/api/v1/admin/pii",
        category="admin",
        service="pii",
        payload={"fiduciary_id": fid, **payload},
        headers={},
        fiduciary_id=fid,
        auth_token={"email": "x@example.org", "role": role},
        operator_id=str(uuid.uuid4()),
    )


# ---- Task 10: guardian verification details and the per-consent audit trail ----------

GUARDIAN = "guardian.rao@example.com"
GUARDIAN_REF = "REF-99887766"
GUARDIAN_PROOF = "proof-secret-77"
APP_77 = "77777777-7777-4777-8777-777777777777"

TRAIL_POLICY = {
    "en": {
        "title": "P",
        "data_processing_purposes": [
            {"id": "care", "name": "Patient care", "data_categories_involved": ["contact", "health"]},
            {"id": "research", "name": "Research", "data_categories_involved": ["health"]},
        ],
        "data_categories_details": [
            {"id": "contact", "name": "Contact details"},
            {"id": "health", "name": "Health records"},
        ],
    }
}


def _console(headers, func, payload, category="admin", method="post"):
    from dpdpcms_py import main
    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    body = {"_func": func, **payload}
    if method == "get":
        return client.get(f"/api/v1/{category}/consent", params=body, headers=headers)
    return client.post(f"/api/v1/{category}/consent", json=body, headers=headers)


def _seed_minor_consent(cur, fid, pol, child="kid-77"):
    """A minor's consent backed by a VERIFIED guardian log carrying evidence."""
    from dpdpcms_py.services.consent import ConsentService

    enc, hmac = _pid(cur, GUARDIAN)
    cur.execute(
        "INSERT INTO data_principal (fiduciary_id, user_id_enc, user_id_hmac, age_category)"
        " VALUES (%s, %s, %s, 'ADULT')",
        (fid, enc, hmac),
    )
    service = ConsentService()
    log = service.record_parent_consent(
        _api_ctx(
            fid,
            {
                "child_principal_id": child,
                "guardian_principal_id": GUARDIAN,
                "verification_mechanism": "EXISTING_ACCOUNT",
                "provider_name": "Clinic desk",
                "verification_ref_id": GUARDIAN_REF,
                "proof_metadata": {"vc_hash": GUARDIAN_PROOF},
            },
        )
    )
    assert log["verification_status"] == "VERIFIED"
    record = service.record_consent(
        _api_ctx(
            fid,
            {
                "user_id": child,
                "policy_id": pol,
                "age_category": "MINOR",
                "verification_log_id": log["verification_log_id"],
                "data_point_consents": [{"id": "care", "consent_granted": True}],
            },
        )
    )
    return log["verification_log_id"], record["data"]["consent_record_id"]


@needs_db
def test_parental_verification_is_masked_and_minor_only(tx):
    from dpdpcms_py import pii

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        fid_b, pol_b = _seed_tenant(cur)
        log_id, minor_record = _seed_minor_consent(cur, fid, pol)
        _, other_tenant_record = _seed_minor_consent(cur, fid_b, pol_b)
        _, email = _reveal_operator(cur, fid, "DPO", "dee")
    adult_record = _grant(fid, pol, "asha")["data"]["consent_record_id"]
    headers = _bearer(email, "DPO")

    for method in ("post", "get"):
        response = _console(
            headers,
            "get_parental_verification",
            {"consent_record_id": minor_record, "fiduciary_id": fid},
            method=method,
        )
        assert response.status_code == 200, (method, response.text)
        body = response.json()
        assert body["verification_log_id"] == log_id
        assert body["provider_name"] == "Clinic desk"
        assert body["verification_status"] == "VERIFIED"
        assert body["verified_at"]
        assert body["guardian_id"] == pii.mask(GUARDIAN) != GUARDIAN
        assert body["verification_ref_id"] == pii.mask(GUARDIAN_REF) != GUARDIAN_REF
        assert body["has_proof_metadata"] is True
        assert body["verification_detail"] is None
        assert "proof_metadata" not in body
        for secret in (GUARDIAN, GUARDIAN_REF, GUARDIAN_PROOF, "vc_hash", "kid-77"):
            assert secret not in response.text

    # An adult's record has no guardian verification; another tenant's record is not found.
    for record in (adult_record, other_tenant_record, str(uuid.uuid4())):
        response = _console(headers, "get_parental_verification", {"consent_record_id": record, "fiduciary_id": fid})
        assert response.status_code == 404, response.text
    response = _console(headers, "get_parental_verification", {"consent_record_id": "nope", "fiduciary_id": fid})
    assert response.status_code == 400
    response = _console(headers, "get_parental_verification", {"fiduciary_id": fid})
    assert response.status_code == 400


def _trail_policy(cur, fid, pol):
    from dpdpcms_py import db

    cur.execute(
        "UPDATE consent_policies SET policy_content = %s WHERE id = %s AND fiduciary_id = %s",
        (db.as_jsonb(TRAIL_POLICY), pol, fid),
    )


def _trail(headers, record, fid):
    response = _console(headers, "get_consent_audit_trail", {"consent_record_id": record, "fiduciary_id": fid})
    assert response.status_code == 200, response.text
    assert "asha" not in response.text
    return response.json()


@needs_db
def test_consent_audit_trail_groups_by_purpose_and_carries_service_id(tx, monkeypatch):
    from dpdpcms_py import audit
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("care", "research"))
        fid_b, _ = _seed_tenant(cur)
        _trail_policy(cur, fid, pol)
        _, email = _reveal_operator(cur, fid, "DPO", "dee")
    service = ConsentService()

    def record(user, research):
        return service.record_consent(
            _api_ctx(
                fid,
                {
                    "user_id": user,
                    "policy_id": pol,
                    "data_point_consents": [
                        {"id": "care", "consent_granted": True},
                        {"id": "research", "consent_granted": research},
                    ],
                },
            )
        )["data"]["consent_record_id"]

    # R1 grants care only (spaces around the id: the same principal as "asha").
    r1 = record(" asha ", False)
    # R2 supersedes R1 and grants two purposes: its audit row has no single purpose.
    r2 = record("asha", True)
    # R3 supersedes R2: research withdrawn.
    r3 = service.withdraw_consent(_api_ctx(fid, {"user_id": "asha", "purpose_ids": ["research"]}))["consent_record_id"]
    # A processor event naming R3 under consent_record_id, with a service id.
    audit.log_event(
        "asha", fid, "PROCESSOR", APP_77, "PROCESSOR_ACKNOWLEDGED", {"consent_record_id": r3}, purpose_id="care"
    )
    # Noise that must not appear: another record, another principal, another
    # tenant, and a plain-text context that is not JSON.
    audit.log_event("asha", fid, "APP", None, "CONSENT_GIVEN", {"record_id": str(uuid.uuid4())})
    audit.log_event("ravi", fid, "APP", None, "CONSENT_GIVEN", {"record_id": r3})
    audit.log_event("asha", fid_b, "APP", None, "CONSENT_GIVEN", {"record_id": r3})
    audit.log_event("asha", fid, "APP", None, "PLAIN_TEXT", f"Operator Access Granted {r3}")
    with tx.cursor() as cur:
        cur.execute("SELECT supersedes_record_id::text AS s FROM consent_records WHERE id = %s", (r3,))
        assert cur.fetchone()["s"] == r2

    headers = _bearer(email, "DPO")
    trail = _trail(headers, r3, fid)
    assert trail["consent_record_id"] == r3
    groups = {g["purpose_id"]: g for g in trail["purposes"]}
    assert [g["purpose_id"] for g in trail["purposes"]] == ["care", "ALL", "research"]
    assert groups["care"]["purpose_name"] == "Patient care"
    assert groups["care"]["fields"] == ["Contact details", "Health records"]
    assert groups["research"]["purpose_name"] == "Research"
    assert groups["research"]["fields"] == ["Health records"]
    assert groups["ALL"]["fields"] == ["Contact details", "Health records"]
    assert [e["audit_action"] for e in groups["care"]["events"]] == ["CONSENT_GIVEN", "PROCESSOR_ACKNOWLEDGED"]
    assert [e["audit_action"] for e in groups["ALL"]["events"]] == ["CONSENT_GIVEN"]
    assert [e["audit_action"] for e in groups["research"]["events"]] == ["CONSENT_WITHDRAWN"]
    processor = groups["care"]["events"][1]
    assert processor["service_type"] == "PROCESSOR" and processor["service_id"] == APP_77
    assert processor["context"] == {"consent_record_id": r3}
    given = groups["care"]["events"][0]
    assert given["service_type"] == "APP" and given["service_id"] is None
    assert given["context"]["record_id"] == r1
    assert groups["ALL"]["events"][0]["context"]["supersedes_record_id"] == r1
    for group in trail["purposes"]:
        for event in group["events"]:
            assert set(event) == {
                "timestamp",
                "audit_action",
                "service_type",
                "service_id",
                "current_log_hash",
                "prev_log_hash",
                "context",
            }
            assert event["timestamp"] and event["current_log_hash"] and event["prev_log_hash"] is not None
    # The chain runs backwards only: the trail of R1 holds its own event.
    first = _trail(headers, r1, fid)
    assert [(g["purpose_id"], [e["audit_action"] for e in g["events"]]) for g in first["purposes"]] == [
        ("care", ["CONSENT_GIVEN"])
    ]

    # Archived years are read too.
    _archive_everything(monkeypatch)
    with tx.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM audit_logs WHERE fiduciary_id = %s", (fid,))
        assert cur.fetchone()["n"] == 0
    archived = _trail(headers, r3, fid)
    assert archived["purposes"] == trail["purposes"]

    # Another tenant's DPO does not see this record.
    with tx.cursor() as cur:
        _, other_email = _reveal_operator(cur, fid_b, "DPO", "dan")
    response = _console(
        _bearer(other_email, "DPO"), "get_consent_audit_trail", {"consent_record_id": r3, "fiduciary_id": fid}
    )
    assert response.status_code == 404


@needs_db
def test_audit_trail_rejects_api_key_and_principal(tx):
    import dataclasses

    from dpdpcms_py import security
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _, minor_record = _seed_minor_consent(cur, fid, pol)
        _, op_email = _reveal_operator(cur, fid, "OPERATOR", "opi")
    principal = {"Authorization": f"Bearer {security.principal_token(fid, 'kid-77')}"}
    api_key = {"X-API-Key": "k", "X-API-Secret": "s"}
    payload = {"consent_record_id": minor_record, "fiduciary_id": fid}
    for func in ("get_consent_audit_trail", "get_parental_verification"):
        for headers in (principal, api_key):
            for method in ("post", "get"):
                response = _console(headers, func, payload, category="client", method=method)
                assert response.status_code == 403, (func, method, response.text)
            assert _console(headers, func, payload).status_code == 401
        # Called directly, the service refuses a caller that is not a console operator.
        for ctx in (
            _api_ctx(fid, {"_func": func, **payload}),
            dataclasses.replace(
                _api_ctx(fid, {"_func": func, **payload}), auth_via_principal_jwt=True, principal_user_id="kid-77"
            ),
            dataclasses.replace(_ctx_as_operator(fid, "DPO", {"_func": func, **payload}), auth_via_principal_jwt=True),
        ):
            with pytest.raises(ApiError) as exc:
                getattr(ConsentService(), func)(ctx)
            assert exc.value.status == 403
    # The trail is an audit-ledger read: an OPERATOR (no audit:read) is refused it.
    response = _console(_bearer(op_email, "OPERATOR"), "get_consent_audit_trail", payload)
    assert response.status_code == 403, response.text


@needs_db
def test_audit_trail_read_is_logged_with_the_consent_record_id(tx):
    import json

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        dpo, email = _reveal_operator(cur, fid, "DPO", "dee")
    record = _grant(fid, pol, "asha")["data"]["consent_record_id"]
    _trail(_bearer(email, "DPO"), record, fid)
    with tx.cursor() as cur:
        cur.execute(
            "SELECT context_details FROM audit_logs WHERE audit_action = 'AUDIT_LOG_READ' AND fiduciary_id = %s",
            (fid,),
        )
        reads = [json.loads(r["context_details"]) for r in cur.fetchall()]
    assert [r["read"] for r in reads] == ["get_consent_audit_trail"]
    assert reads[0]["filters"]["consent_record_id"] == record
    assert reads[0]["rows_returned"] == 1


@needs_db
def test_erased_principal_record_has_an_empty_trail(tx):
    from dpdpcms_py.services.compliance import erase_cms_copy

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _, email = _reveal_operator(cur, fid, "DPO", "dee")
    record = _grant(fid, pol, "asha")["data"]["consent_record_id"]
    headers = _bearer(email, "DPO")
    assert [g["purpose_id"] for g in _trail(headers, record, fid)["purposes"]] == ["care"]
    erase_cms_copy(fid, "asha")
    assert _trail(headers, record, fid)["purposes"] == []


@needs_db
def test_audit_trail_without_a_decryptable_principal_is_empty(tx, monkeypatch):
    from dpdpcms_py import audit

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _, email = _reveal_operator(cur, fid, "DPO", "dee")
    record = _grant(fid, pol, "asha")["data"]["consent_record_id"]
    # A NULL decrypt never derives a pseudonym (pseudonym("") is a real hash).
    from dpdpcms_py.services import consent as consent_mod

    monkeypatch.setattr(
        consent_mod.pii, "dec_sql", lambda column: "CASE WHEN %s::text IS NULL THEN NULL ELSE NULL::text END"
    )
    real = audit.principal_pseudonym

    def pseudonym(value):
        if not value:
            pytest.fail("pseudonym derived for a NULL principal")
        return real(value)

    monkeypatch.setattr(audit, "principal_pseudonym", pseudonym)
    assert _trail(_bearer(email, "DPO"), record, fid)["purposes"] == []


# ---- Task 11: DPO console UI ------------------------------------------------------------


def _dpo_page(name):
    from pathlib import Path

    return (Path(__file__).resolve().parents[2] / "web" / "console" / "dpo" / name).read_text(encoding="utf-8")


def test_dpo_pages_have_no_inline_handlers_and_call_new_funcs():
    import re

    for page in ("principals", "compliance", "grievances"):
        html = _dpo_page(f"{page}.html")
        assert not re.search(r"<script(?![^>]*\bsrc\s*=\s*[\"'])[^>]*>", html, re.I), f"inline <script> in {page}"
        assert not re.search(r" on[a-z]+=", html, re.I), f"inline event handler in {page}"
        # The shared reveal control loads before the page script that uses it.
        shared = html.index('<script src="reveal.js"></script>')
        assert shared < html.index(f'<script src="{page}.js"></script>'), f"{page}.html does not load reveal.js first"
        assert "DpoReveal." in _dpo_page(f"{page}.js"), f"{page}.js does not use the shared reveal control"
    principals = _dpo_page("principals.js")
    for func in ("get_consent_audit_trail", "get_parental_verification", "withdraw_consent"):
        assert func in principals, f"principals.js does not call {func}"
    reveal = _dpo_page("reveal.js")
    assert '"_func": "reveal_user_id"' in reveal and "/api/v1/admin/pii" in reveal
    assert "Reveal — this action is logged" in reveal
    for page in ("reveal.js", "principals.js", "compliance.js", "grievances.js"):
        script = _dpo_page(page)
        # One reveal implementation: no page carries its own reveal_user_id call.
        assert page == "reveal.js" or '"reveal_user_id"' not in script, f"{page} calls reveal_user_id itself"
        # A revealed value is never persisted in the browser.
        assert not re.search(r"localStorage\.setItem", script), f"{page} writes localStorage"
        assert not re.search(r"https?://", script), f"{page} loads a remote URL"
        assert not re.search(r"\.innerHTML\s*=[^;]*\bfields\b", script), f"{page} writes revealed values as markup"


def test_compliance_console_sends_no_filter_the_service_ignores():
    script = _dpo_page("compliance.js")
    start = script.index('"_func": "list_purge_requests"')
    payload = script[script.rindex("{", 0, start) : script.index("}", start)]
    assert '"search"' not in payload


def test_grievance_console_sends_the_filter_keys_list_grievances_reads():
    script = _dpo_page("grievances.js")
    start = script.index('"_func": "list_grievances"')
    payload = script[script.rindex("{", 0, start) : script.index("}", start)]
    assert '"user_id"' in payload and '"status"' in payload
    assert '"search"' not in payload and '"status_filter"' not in payload


@needs_db
def test_list_principals_gives_the_console_a_user_ref_it_can_reveal(tx):
    from dpdpcms_py import pii

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _, email = _reveal_operator(cur, fid, "DPO", "dee")
    _grant(fid, pol, "asha@example.org")
    headers = _bearer(email, "DPO")
    response = _console(headers, "list_principals", {"fiduciary_id": fid})
    assert response.status_code == 200, response.text
    [row] = response.json()
    assert row["user_id"] == pii.mask("asha@example.org")
    assert row["user_ref"] == pii.hmac_hex("asha@example.org")
    assert "user_id_hmac" not in row and "user_id_enc" not in row
    revealed = _reveal(headers, {"source": "data_principal", "fiduciary_id": fid, "user_ref": row["user_ref"]})
    assert revealed.status_code == 200, revealed.text
    assert revealed.json()["fields"] == {"user_id": "asha@example.org"}


@needs_db
def test_operator_reads_consent_history_by_user_ref_with_masked_ids(tx):
    from dpdpcms_py import pii

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _, email = _reveal_operator(cur, fid, "OPERATOR", "oli")
    _grant(fid, pol, "asha@example.org")
    headers = _bearer(email, "OPERATOR")
    ref = pii.hmac_hex("asha@example.org")
    by_ref = _console(headers, "list_consent_history", {"fiduciary_id": fid, "user_ref": ref})
    by_id = _console(headers, "list_consent_history", {"fiduciary_id": fid, "user_id": "asha@example.org"})
    assert by_ref.status_code == 200, by_ref.text
    assert by_ref.json() == by_id.json() and len(by_ref.json()) == 1
    assert by_ref.json()[0]["user_id"] == pii.mask("asha@example.org")
    assert "asha@example.org" not in by_ref.text
    # A lookup by reference discloses nothing, so it is not a reveal.
    with tx.cursor() as cur:
        assert _reveal_rows(cur) == []
    bad = _console(headers, "list_consent_history", {"fiduciary_id": fid, "user_ref": "not-a-hash"})
    assert bad.status_code == 400, bad.text


@needs_db
def test_user_ref_history_lookup_stays_in_the_callers_tenant(tx):
    from dpdpcms_py import pii

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        other, other_pol = _seed_tenant(cur)
        _, email = _reveal_operator(cur, fid, "DPO", "dee")
    _grant(other, other_pol, "ravi@example.org")
    ref = pii.hmac_hex("ravi@example.org")
    headers = _bearer(email, "DPO")
    own = _console(headers, "list_consent_history", {"fiduciary_id": fid, "user_ref": ref})
    assert own.status_code == 200 and own.json() == []
    cross = _console(headers, "list_consent_history", {"fiduciary_id": other, "user_ref": ref})
    assert cross.status_code in (200, 403), cross.text
    assert "ravi" not in cross.text and (cross.status_code == 403 or cross.json() == [])


@needs_db
def test_api_key_caller_cannot_look_up_history_by_user_ref(tx):
    from dpdpcms_py import pii
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
    _grant(fid, pol, "asha@example.org")
    with pytest.raises(ApiError) as err:
        ConsentService().list_consent_history(_api_ctx(fid, {"user_ref": pii.hmac_hex("asha@example.org")}))
    assert err.value.status == 403


# ---- Final review fixes -----------------------------------------------------------------


def test_otp_subject_trims_spaces_but_keeps_case():
    from dpdpcms_py import principal_otp

    assert principal_otp.subject_key(FID, " abc123 ") == principal_otp.subject_key(FID, "abc123")
    assert principal_otp.subject_key(FID, "abc123") != principal_otp.subject_key(FID, "ABC123")


@needs_db
def test_otp_issued_for_one_principal_does_not_log_in_a_case_variant(tx, monkeypatch):
    from dpdpcms_py import principal_otp, webhooks
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.consent import PrincipalService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    codes = []
    real_encrypt = principal_otp.encrypt_code

    def capture(code):
        codes.append(code)
        return real_encrypt(code)

    monkeypatch.setattr(principal_otp, "encrypt_code", capture)
    monkeypatch.setattr(webhooks, "queue_webhook", lambda *a, **k: None)

    def call(func, payload):
        ctx = _ctx(fid, {"fiduciary_id": fid, **payload})
        return getattr(PrincipalService(), func)(ctx)

    call("request_principal_otp", {"user_id": "abc123"})
    with pytest.raises(ApiError) as err:
        call("principal_login", {"user_id": "ABC123", "otp": codes[-1]})
    assert err.value.status == 401
    # Spaces are not part of the id: the padded form is the same principal.
    out = call("principal_login", {"user_id": " abc123 ", "otp": codes[-1]})
    assert out["token"] and out["user_id"] == "abc123"


def _log_archived_and_live(monkeypatch, cur, fid, action):
    """One `action` row in the oldest live year (then archived) and one in a live year."""
    from datetime import datetime

    from dpdpcms_py import audit

    year = _live_partition_years(cur)[0]
    _log_at(monkeypatch, datetime(year, 3, 1), action=action, fid=fid)
    _archive_everything(monkeypatch)
    assert f"audit_logs_y{year}_archive" in audit.ledger_source()
    _log_at(monkeypatch, datetime(2200, 6, 1), action=action, fid=fid)
    return year


@needs_db
def test_audit_export_includes_archived_years(tx, tmp_path, monkeypatch):
    import csv
    import dataclasses
    import json

    from dpdpcms_py import jobs
    from dpdpcms_py.config import settings

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        year = _log_archived_and_live(monkeypatch, cur, fid, "EXPORT_EVENT")
    monkeypatch.setattr(jobs, "settings", dataclasses.replace(settings, export_path=tmp_path))
    path = jobs._write_export(
        {
            "id": str(uuid.uuid4()),
            "fiduciary_id": fid,
            "subtype": "AUDIT",
            "start_date": f"{year}-01-01",
            "end_date": "2200-12-31",
        }
    )
    with path.open(encoding="utf-8") as handle:
        stamps = sorted(r["timestamp"][:4] for r in csv.DictReader(handle) if r["audit_action"] == "EXPORT_EVENT")
    assert stamps == [str(year), "2200"]
    verdict = json.loads(path.with_suffix(".verification.json").read_text(encoding="utf-8"))
    assert verdict["attestation"] == "INTACT"


@needs_db
def test_access_report_includes_archived_years(tx, monkeypatch):
    from dpdpcms_py.services.governance import AuditService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        year = _log_archived_and_live(monkeypatch, cur, fid, "LOGIN_SUCCESS")
    report = AuditService().list_access_report(
        _ctx(fid, {"start_date": f"{year}-01-01", "end_date": "2200-12-31T23:59:59"})
    )
    years = sorted(str(e["timestamp"])[:4] for e in report["events"] if e["audit_action"] == "LOGIN_SUCCESS")
    assert years == [str(year), "2200"]


@needs_db
def test_pending_grievance_queue_carries_no_ciphertext_and_masks_the_principal(tx):
    from dpdpcms_py import pii
    from dpdpcms_py.services.admin import AdminDashService
    from tests.test_integration_db import _ASHA_ENC, _ASHA_HMAC

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO grievances (user_id_enc, user_id_hmac, fiduciary_id, type, subject, description)"
            f" VALUES ({_ASHA_ENC}, {_ASHA_HMAC}, %s, 'GENERAL_COMPLAINT', 's', 'd')",
            (fid,),
        )
    (row,) = AdminDashService().list_pending_grievances(_ctx(fid, {"fiduciary_id": fid}, operator_id="op-1"))
    assert "user_id_enc" not in row and "user_id_hmac" not in row
    assert row["user_id"] == pii.mask("asha") and row["grievance_id"]


@needs_db
def test_dashboard_access_logs_decrypt_the_ip_and_read_archived_years(tx, monkeypatch):
    from datetime import UTC, datetime

    from dpdpcms_py import audit
    from dpdpcms_py.services.admin import AdminDashService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        year = _live_partition_years(cur)[0]
    monkeypatch.setattr(audit, "_now", lambda: datetime(year, 3, 1, tzinfo=UTC))
    audit.log_event("asha", fid, "SYSTEM", None, "DASH_EVENT", {}, source_ip="203.0.113.7")
    _archive_everything(monkeypatch)
    rows = AdminDashService().list_access_logs(_ctx(fid, {"limit": 50}))
    (row,) = [r for r in rows if r["audit_action"] == "DASH_EVENT"]
    assert row["source_ip"] == "203.0.113.7"
