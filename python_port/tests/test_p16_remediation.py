"""Workbook revision 17 (P16-01..05) regressions.

DB-backed tests reuse the transaction-per-test fixture and seed helpers of
test_integration_db.py and skip without a live Postgres; the rest are unit
tests.
"""

import dataclasses
import json
import os
import shutil
import subprocess
import uuid
from datetime import timedelta

import pytest
from tests.test_integration_db import _DB_READY, REPO, _seed_consent, _seed_tenant
from tests.test_pii_port import (
    _api_ctx,
    _bearer,
    _console,
    _reveal,
    _reveal_operator,
    _seed_revealable,
    _source_payload,
)

needs_db = pytest.mark.skipif(not _DB_READY, reason="no live Postgres configured")


def _audit_rows(cur, fid, action):
    cur.execute(
        "SELECT service_type, initiator, context_details FROM audit_logs WHERE fiduciary_id = %s AND audit_action = %s",
        (fid, action),
    )
    return cur.fetchall()


def _active(cur, fid):
    cur.execute("SELECT count(*) AS n FROM consent_records WHERE fiduciary_id = %s AND is_active_consent", (fid,))
    return cur.fetchone()["n"]


# ---- P16-01: an operator's withdrawal is attributed to that operator ---------------------


@needs_db
@pytest.mark.parametrize(
    "func, action", [("withdraw_consent", "CONSENT_WITHDRAWN"), ("erasure_request", "ERASURE_REQUESTED")]
)
def test_console_withdrawal_names_the_operator(tx, func, action):
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        dpo, email = _reveal_operator(cur, fid, "DPO", "dee")
    payload = {"user_id": "asha", "fiduciary_id": fid, "reason": "Principal asked by phone on 20 Oct"}
    if func == "withdraw_consent":
        payload["purpose_ids"] = ["care"]
    response = _console(_bearer(email, "DPO"), func, payload)
    assert response.status_code == 200, response.text
    with tx.cursor() as cur:
        [row] = _audit_rows(cur, fid, action)
    assert row["initiator"] == f"OPERATOR:{dpo}"
    assert row["service_type"] == "DPO_CONSOLE"


@needs_db
def test_console_withdrawal_without_a_basis_is_refused(tx):
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        _, email = _reveal_operator(cur, fid, "DPO", "dee")
    for reason in (None, "", "   ", "too short"):
        payload = {"user_id": "asha", "fiduciary_id": fid, "purpose_ids": ["care"]}
        if reason is not None:
            payload["reason"] = reason
        response = _console(_bearer(email, "DPO"), "withdraw_consent", payload)
        assert response.status_code == 400, response.text
    with tx.cursor() as cur:
        assert _active(cur, fid) == 1
        assert _audit_rows(cur, fid, "CONSENT_WITHDRAWN") == []


@needs_db
def test_console_withdrawal_links_a_grievance_of_its_own_tenant(tx):
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        other, other_pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        _, email = _reveal_operator(cur, fid, "DPO", "dee")
        refs = _seed_revealable(cur, other, other_pol)  # a grievance in ANOTHER tenant
        cur.execute("SELECT reference_number FROM grievances WHERE id = %s", (refs["grievance"],))
        foreign = cur.fetchone()["reference_number"]
        cur.execute(
            "INSERT INTO grievances (user_id_enc, user_id_hmac, fiduciary_id, type, subject, description,"
            " reference_number) SELECT user_id_enc, user_id_hmac, %s, type, subject, description, 'GRV-OWN-1'"
            " FROM grievances WHERE id = %s RETURNING id",
            (fid, refs["grievance"]),
        )
        own_id = str(cur.fetchone()["id"])
    base = {"user_id": "asha", "fiduciary_id": fid, "purpose_ids": ["care"]}
    response = _console(_bearer(email, "DPO"), "withdraw_consent", {**base, "grievance_reference": foreign})
    assert response.status_code == 400, response.text
    response = _console(_bearer(email, "DPO"), "withdraw_consent", {**base, "grievance_reference": "GRV-OWN-1"})
    assert response.status_code == 200, response.text
    with tx.cursor() as cur:
        [row] = _audit_rows(cur, fid, "CONSENT_WITHDRAWN")
    context = json.loads(row["context_details"])
    assert context["grievance_id"] == own_id and context["grievance_reference"] == "GRV-OWN-1"


@needs_db
def test_integrator_and_principal_withdrawals_keep_their_attribution(tx):
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
    # An API key needs no reason: the integrator relays the principal's own act.
    ConsentService().withdraw_consent(_api_ctx(fid, {"user_id": "asha", "purpose_ids": ["care"]}))
    with tx.cursor() as cur:
        [row] = _audit_rows(cur, fid, "CONSENT_WITHDRAWN")
    assert (row["service_type"], row["initiator"]) == ("APP", "INTEGRATOR")


# ---- P16-02: the pre-db/32 ledger stays append-only and is verified against its seal -----


def _legacy_ledger(cur, rows=3):
    """A stand-in for audit_logs_legacy_pre32: chained rows, triggers and a seal as db/37 leaves them."""
    from dpdpcms_py import audit

    # A fresh install's db/32 already set aside the (empty) db/01 table and
    # db/37 sealed it; replace both inside the test's transaction.
    cur.execute("DROP TABLE IF EXISTS audit_logs_legacy_pre32")
    cur.execute("ALTER TABLE audit_legacy_ledger_seal DISABLE TRIGGER trg_audit_legacy_ledger_seal_append_only")
    cur.execute("DELETE FROM audit_legacy_ledger_seal")
    cur.execute("ALTER TABLE audit_legacy_ledger_seal ENABLE TRIGGER trg_audit_legacy_ledger_seal_append_only")
    cur.execute("ALTER TABLE audit_legacy_ledger_verifications DISABLE TRIGGER USER")
    cur.execute("DELETE FROM audit_legacy_ledger_verifications")
    cur.execute("ALTER TABLE audit_legacy_ledger_verifications ENABLE TRIGGER USER")
    cur.execute("CREATE TABLE audit_logs_legacy_pre32 (LIKE audit_logs INCLUDING DEFAULTS)")
    previous = ""
    stamp = audit._now().replace(tzinfo=None) - timedelta(days=400)
    for index in range(rows):
        row = {
            "id": str(uuid.uuid4()),
            "fiduciary_id": None,
            "timestamp": stamp + timedelta(minutes=index),
            "user_id": "SYSTEM",
            "service_type": "SYSTEM",
            "service_id": None,
            "audit_action": f"LEGACY_{index}",
            "context_details": "{}",
            "purpose_id": None,
            "consent_status": None,
            "initiator": None,
            "source_ip": None,
        }
        current = audit.row_hash(previous, row)
        cur.execute(
            "INSERT INTO audit_logs_legacy_pre32 (id, timestamp, user_id, service_type, audit_action,"
            " context_details, prev_log_hash, current_log_hash, system_metadata)"
            " VALUES (%(id)s, %(timestamp)s, %(user_id)s, %(service_type)s, %(audit_action)s, %(context_details)s,"
            " %(prev)s, %(current)s, %(meta)s)",
            {**row, "prev": previous, "current": current, "meta": json.dumps({"hash_v": audit.HASH_VERSION})},
        )
        previous = current
    cur.execute(
        "CREATE TRIGGER trg_audit_logs_no_update_delete BEFORE UPDATE OR DELETE ON audit_logs_legacy_pre32"
        " FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only()"
    )
    cur.execute(
        "INSERT INTO audit_legacy_ledger_seal (table_name, row_count, head_hash) VALUES ('audit_logs_legacy_pre32', %s, %s)",
        (rows, previous),
    )


@needs_db
def test_legacy_ledger_verifies_against_its_seal(tx):
    from dpdpcms_py import audit

    with tx.cursor() as cur:
        _legacy_ledger(cur)
    out = audit.verify_legacy_ledger()
    assert out["intact"] is True and out["rows"] == 3 and out["head_matches_seal"]
    assert audit.latest_legacy_verification()["intact"] is True
    # Once verified, the weekly walk does not repeat inside its interval.
    assert audit.verify_legacy_ledger() == {"skipped": True}


@needs_db
def test_legacy_ledger_rows_cannot_be_edited_and_a_bypass_is_detected(tx):
    import psycopg
    from dpdpcms_py import audit

    with tx.cursor() as cur:
        _legacy_ledger(cur)
        with pytest.raises(psycopg.Error, match="append-only"), tx.transaction():
            cur.execute("UPDATE audit_logs_legacy_pre32 SET context_details = 'TAMPERED'")
        # A table owner can still disable a trigger; the seal and the hashes catch it.
        cur.execute("ALTER TABLE audit_logs_legacy_pre32 DISABLE TRIGGER trg_audit_logs_no_update_delete")
        cur.execute("UPDATE audit_logs_legacy_pre32 SET context_details = 'TAMPERED' WHERE audit_action = 'LEGACY_1'")
    out = audit.verify_legacy_ledger()
    assert out["intact"] is False and out["broken_count"] >= 1


@needs_db
def test_legacy_ledger_seal_and_verdicts_are_append_only(tx):
    import psycopg

    with tx.cursor() as cur:
        _legacy_ledger(cur)
        for sql in (
            "UPDATE audit_legacy_ledger_seal SET row_count = 0",
            "DELETE FROM audit_legacy_ledger_seal",
        ):
            with pytest.raises(psycopg.Error, match="append-only"), tx.transaction():
                cur.execute(sql)


def test_db32_no_longer_drops_the_legacy_triggers():
    text = (REPO / "db" / "32_partition_audit_logs.sql").read_text(encoding="utf-8")
    assert "DROP TRIGGER" not in text


PSQL = shutil.which("psql")


@needs_db
@pytest.mark.skipif(not PSQL, reason="psql not on PATH (CI provisions with it)")
def test_upgrade_from_db31_keeps_the_legacy_ledger_append_only_and_sealed():
    """The workbook's executed upgrade, db/01..31 then db/32..37 over a seeded row, as a test."""
    import psycopg
    from dpdpcms_py.config import settings

    name = f"p16_upgrade_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(settings.db_dsn, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    info = psycopg.conninfo.conninfo_to_dict(settings.db_dsn)
    env = {
        **os.environ,
        "PGHOST": str(info.get("host") or "localhost"),
        "PGPORT": str(info.get("port") or 5432),
        "PGUSER": str(info.get("user")),
        "PGPASSWORD": str(info.get("password") or ""),
        "PGDATABASE": name,
    }

    def apply(path):
        subprocess.run([PSQL, "-q", "-v", "ON_ERROR_STOP=1", "-f", str(path)], env=env, check=True, capture_output=True)

    try:
        files = sorted((REPO / "db").glob("*.sql"))
        for path in files:
            if path.name < "32":
                apply(path)
        dsn = psycopg.conninfo.make_conninfo(settings.db_dsn, dbname=name)
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(
                "INSERT INTO audit_logs (timestamp, user_id, service_type, audit_action, context_details,"
                " prev_log_hash, current_log_hash) VALUES (NOW(), 'SYSTEM', 'SYSTEM', 'SEED', '{}', '', 'h1')"
            )
        for path in files:
            if path.name >= "32":
                apply(path)
        with psycopg.connect(dsn, autocommit=True) as conn:
            with pytest.raises(psycopg.Error, match="append-only"):
                conn.execute("UPDATE audit_logs_legacy_pre32 SET context_details = 'TAMPERED'")
            seal = conn.execute("SELECT row_count, head_hash FROM audit_legacy_ledger_seal").fetchone()
            assert seal == (1, "h1")
    finally:
        with psycopg.connect(settings.db_dsn, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


# ---- P16-03: principal ids in queued payloads are sealed at rest -------------------------


def _payloads(cur, table, fid):
    cur.execute(f"SELECT id, payload, payload::text AS j FROM {table} WHERE fiduciary_id = %s", (fid,))
    return cur.fetchall()


@needs_db
def test_withdrawal_payloads_hold_no_plaintext_principal_id(tx, monkeypatch):
    from dpdpcms_py import pii
    from dpdpcms_py.services.alerts import AlertService
    from dpdpcms_py.services.consent import ConsentService

    pid = "ramesh.kumar@example.org"
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, pid)
    ConsentService().withdraw_consent(_api_ctx(fid, {"user_id": pid, "purpose_ids": ["care"]}))
    with tx.cursor() as cur:
        for table in ("alerts", "webhook_deliveries"):
            rows = _payloads(cur, table, fid)
            assert rows, f"no {table} rows"
            assert all(pid not in row["j"] for row in rows), f"plaintext principal id in {table}.payload"
            sealed = [row["payload"] for row in rows if "user_id_enc" in row["payload"]]
            assert sealed and all(p["user_id_hmac"] == pii.hmac_hex(pid) for p in sealed)
    # An API key reads the alert opened; a console operator reads it masked.
    alerts = AlertService().list_alerts(_api_ctx(fid, {"fiduciary_id": fid}))
    assert any(a["payload"].get("user_id") == pid for a in alerts)
    assert all("user_id_enc" not in a["payload"] for a in alerts)
    from tests.test_pii_port import _ctx_as_operator

    masked = AlertService().list_alerts(_ctx_as_operator(fid, "DPO", {}))
    assert all(pid not in json.dumps(a["payload"]) for a in masked)


@needs_db
def test_dispatcher_opens_the_payload_only_for_the_post(tx, monkeypatch):
    from dpdpcms_py import webhooks
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        cur.execute(
            "INSERT INTO webhook_configs (fiduciary_id, category, webhook_url, secret_enc, enabled)"
            " VALUES (%s, 'NOTIFICATION', 'https://hooks.example.in/x', '', TRUE)",
            (fid,),
        )
    ConsentService().withdraw_consent(_api_ctx(fid, {"user_id": "asha", "purpose_ids": ["care"]}))
    sent = []
    monkeypatch.setattr(webhooks, "post_json", lambda url, body, headers, timeout: (sent.append(body), (200, "ok"))[1])
    webhooks.process_pending_webhooks()
    assert any(body["data"].get("user_id") == "asha" for body in sent)
    assert all("user_id_enc" not in body["data"] for body in sent)


@needs_db
def test_erasure_reseals_payloads_to_the_token(tx):
    from dpdpcms_py import pii
    from dpdpcms_py.services.compliance import erase_cms_copy
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
    ConsentService().withdraw_consent(_api_ctx(fid, {"user_id": "asha", "purpose_ids": ["care"]}))
    erase_cms_copy(fid, "asha")
    with tx.cursor() as cur:
        for table in ("alerts", "webhook_deliveries"):
            rows = _payloads(cur, table, fid)
            assert all(pii.hmac_hex("asha") not in row["j"] for row in rows), table
            opened = pii.open_principal_keys([row["payload"] for row in rows])
            ids = {p.get("user_id") for p in opened} - {None}
            assert ids and all(i.startswith("erased:") for i in ids), (table, ids)


@needs_db
def test_old_plaintext_payloads_are_sealed_in_place_and_the_floor_still_holds(tx):
    import psycopg
    from dpdpcms_py import db, jobs, pii

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO webhook_deliveries (fiduciary_id, category, event_type, payload)"
            " VALUES (%s, 'NOTIFICATION', 'CONSENT_WITHDRAWN', %s) RETURNING id",
            (fid, db.as_jsonb({"user_id": "asha", "purpose_ids": ["care"], "nested": {"guardian_id": "ravi"}})),
        )
        wid = cur.fetchone()["id"]
        cur.execute(
            "INSERT INTO alerts (fiduciary_id, recipient_type, recipient_id_enc, recipient_id_hmac, alert_type, payload)"
            " VALUES (%s, 'FIDUCIARY', 'x', 'y', 'CONSENT_WITHDRAWN', %s)",
            (fid, db.as_jsonb({"user_id": "asha"})),
        )
    out = jobs.seal_queued_payloads()
    assert out["webhook_deliveries"] >= 1 and out["alerts"] >= 1
    with tx.cursor() as cur:
        for table in ("alerts", "webhook_deliveries"):
            assert all("asha" not in row["j"] and "ravi" not in row["j"] for row in _payloads(cur, table, fid))
        cur.execute("SELECT payload FROM webhook_deliveries WHERE id = %s", (wid,))
        payload = cur.fetchone()["payload"]
        assert pii.open_principal_keys([payload])[0] == {
            "user_id": "asha",
            "purpose_ids": ["care"],
            "nested": {"guardian_id": "ravi"},
        }
        # The floor still refuses any other change: a different principal, a
        # forged HMAC, or a non-principal key.
        other = pii.seal_principal_keys({"user_id": "mallory"})
        for forged in (
            {**payload, **other},
            {**payload, "user_id_hmac": pii.hmac_hex("mallory")},
            {**payload, "purpose_ids": ["research"]},
        ):
            with pytest.raises(psycopg.Error, match="Rule 6"), tx.transaction():
                cur.execute("UPDATE webhook_deliveries SET payload = %s WHERE id = %s", (db.as_jsonb(forged), wid))
    assert jobs.seal_queued_payloads() == {"alerts": 0, "webhook_deliveries": 0}


def test_seal_and_open_round_trip_any_shape(monkeypatch):
    from dpdpcms_py import pii

    fake = {"enc": lambda v: "E:" + v, "dec": lambda v: v[2:]}

    def crypt(sql, values):
        return [fake["enc" if "encrypt" in sql else "dec"](v) for v in values]

    monkeypatch.setattr(pii, "_crypt_many", crypt)
    value = {
        "user_id": " asha ",
        "list": [{"nominee_id": 42}, {"recipient_id": None}],
        "note": "user_id stays",
        "other_hmac": "kept",
    }
    sealed = pii.seal_principal_keys(value)
    assert "user_id" not in sealed and sealed["user_id_hmac"] == pii.hmac_hex(" asha ")
    assert sealed["list"][0]["nominee_id_json"] is True and sealed["list"][1] == {"recipient_id": None}
    assert pii.open_principal_keys([sealed]) == [value]
    token = "erased:t"
    resealed = pii.reseal_matching(sealed, pii.hmac_hex("asha"), "E:" + token, pii.hmac_hex(token))
    assert pii.open_principal_keys([resealed])[0]["user_id"] == token
    assert pii.reseal_matching(sealed, "nope", "x", "y") is None


@needs_db
def test_sql_principal_keys_match_python(tx):
    from dpdpcms_py import pii

    with tx.cursor() as cur:
        cur.execute("SELECT tsi_principal_keys() AS k")
        assert set(cur.fetchone()["k"]) == set(pii.PRINCIPAL_KEYS)


# ---- P16-04: lookup HMACs use their own key -------------------------------------------


def test_production_needs_a_distinct_lookup_key(monkeypatch):
    from dpdpcms_py import config

    monkeypatch.setenv("DB_ENCRYPTION_KEY", "e" * 40)
    monkeypatch.delenv("PII_LOOKUP_KEY", raising=False)
    with pytest.raises(RuntimeError, match="PII_LOOKUP_KEY"):
        config._pii_lookup_key("production")
    assert config._pii_lookup_key("staging") == "e" * 40
    monkeypatch.setenv("PII_LOOKUP_KEY", "e" * 40)
    with pytest.raises(RuntimeError, match="differ"):
        config._pii_lookup_key("production")
    monkeypatch.setenv("PII_LOOKUP_KEY", "l" * 40)
    assert config._pii_lookup_key("production") == "l" * 40


def test_lookup_hmac_is_not_keyed_by_the_encryption_key(monkeypatch):
    import hashlib
    import hmac

    from dpdpcms_py import pii
    from dpdpcms_py.config import settings

    monkeypatch.setattr(pii, "settings", dataclasses.replace(settings, pii_lookup_key="l" * 40))
    assert pii.hmac_params("asha") == ("asha", "l" * 40)
    assert pii.hmac_hex("asha") == hmac.new(b"l" * 40, b"asha", hashlib.sha256).hexdigest()
    assert pii.enc_params("asha") == ("asha", settings.db_encryption_key)


@needs_db
def test_rekey_moves_every_lookup_to_a_new_key(tx, monkeypatch):
    from dpdpcms_py import db, pii, rekey_lookup
    from dpdpcms_py.config import settings
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
    ConsentService().withdraw_consent(_api_ctx(fid, {"user_id": "asha", "purpose_ids": ["care"]}))
    new_key = "n" * 40
    rekeyed = dataclasses.replace(settings, pii_lookup_key=new_key)
    for module in (pii, rekey_lookup, db):
        monkeypatch.setattr(module, "settings", rekeyed)
    with tx.cursor() as cur:
        cur.execute("SELECT set_config('app.lookup_key', %s, false)", (new_key,))
    counts = rekey_lookup.rekey()
    assert counts["consent_records.user_id"] >= 2 and counts["notification_deliveries.recipient"] >= 0
    assert "operators.email" not in counts
    with tx.cursor() as cur:
        cur.execute(
            f"SELECT count(*) AS n FROM consent_records WHERE fiduciary_id = %s AND {pii.match_sql('user_id')}",
            (fid, *pii.hmac_params("asha")),
        )
        assert cur.fetchone()["n"] >= 2
        sealed = [r["payload"] for r in _payloads(cur, "webhook_deliveries", fid) if "user_id_enc" in r["payload"]]
        assert sealed and all(p["user_id_hmac"] == pii.hmac_hex("asha") for p in sealed)
    # The principal's history is found again under the new key.
    assert ConsentService().list_consent_history(_api_ctx(fid, {"user_id": "asha", "fiduciary_id": fid}))


# ---- P16-05: reveal volume is capped per day and alerted -------------------------------


@needs_db
def test_daily_reveal_ceiling(tx, monkeypatch):
    from dpdpcms_py import audit
    from dpdpcms_py.services import pii as reveal

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        refs = _seed_revealable(cur, fid, pol)
        dpo, email = _reveal_operator(cur, fid, "DPO", "dee")
        # REVEAL_DAILY_LIMIT reveals spread over the last 23 hours (rows written
        # directly: log_event keeps timestamps increasing, so it cannot backdate):
        # never REVEAL_LIMIT in one minute, so only the daily ceiling can refuse.
        cur.execute(
            "INSERT INTO audit_logs (timestamp, fiduciary_id, user_id, service_type, audit_action, initiator)"
            " SELECT (NOW() AT TIME ZONE 'UTC') - INTERVAL '23 hours' + make_interval(mins => 5 * g),"
            " %s, 'x', %s, %s, %s FROM generate_series(0, %s - 1) AS g",
            (fid, reveal.REVEAL_SERVICE_TYPE, reveal.REVEAL_ACTION, f"OPERATOR:{dpo}", reveal.REVEAL_DAILY_LIMIT),
        )
    real_now = audit._now
    response = _reveal(_bearer(email, "DPO"), _source_payload(fid, "grievance", refs["grievance"]))
    assert response.status_code == 429 and "Daily" in response.text and "asha" not in response.text
    # A day after the oldest of them, the window has room again.
    monkeypatch.setattr(audit, "_now", lambda: real_now() + timedelta(hours=1, minutes=1))
    assert _reveal(_bearer(email, "DPO"), _source_payload(fid, "grievance", refs["grievance"])).status_code == 200


@needs_db
def test_reveal_volume_raises_one_alert_per_operator_per_window(tx):
    from dpdpcms_py import jobs
    from dpdpcms_py.audit import log_event
    from dpdpcms_py.services import pii as reveal

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    operator = f"OPERATOR:{uuid.uuid4()}"
    for _ in range(jobs.REVEAL_VOLUME_THRESHOLD):
        log_event("asha", fid, reveal.REVEAL_SERVICE_TYPE, None, reveal.REVEAL_ACTION, {}, initiator=operator)
    assert jobs.flag_security_anomalies()["alerts_raised"] >= 1
    jobs.flag_security_anomalies()
    with tx.cursor() as cur:
        cur.execute(
            "SELECT event_ref_id, payload FROM alerts WHERE fiduciary_id = %s AND alert_type = 'SECURITY_PII_REVEAL_VOLUME'",
            (fid,),
        )
        rows = cur.fetchall()
        cur.execute(
            "SELECT count(*) AS n FROM notifications WHERE fiduciary_id = %s AND notification_type = 'SECURITY_PII_REVEAL_VOLUME'",
            (fid,),
        )
        notices = cur.fetchone()["n"]
    assert len(rows) == 1 and rows[0]["event_ref_id"] == operator and notices == 1
    assert rows[0]["payload"]["reveals"] == jobs.REVEAL_VOLUME_THRESHOLD
