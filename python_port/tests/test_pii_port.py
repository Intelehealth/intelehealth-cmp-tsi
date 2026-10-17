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
            f"SELECT {pii.dec_sql('user_id_enc')} AS u, user_id_hmac, ip_address, user_agent FROM consent_records"
            " WHERE fiduciary_id = %s",
            (key, fid),
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
