"""Workbook v10 (P12-xx, INV-07/08) regressions.

DB-backed tests reuse the transaction-per-test fixture and seed helpers of
test_integration_db.py and skip without a live Postgres; the rest are unit
tests.
"""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from tests.test_integration_db import (
    _DB_READY,
    REPO,
    _ctx,
    _seed_consent,
    _seed_policy_version,
    _seed_purge,
    _seed_tenant,
    real_db,
)

needs_db = pytest.mark.skipif(not _DB_READY, reason="no live Postgres configured")


# ---- P12-01 / P12-02: consent_expiry is never the caller's to set ------------------


@pytest.mark.parametrize("expiry", ["2027-01-01", "2027-01-01T00:00:00+05:30"])
def test_caller_supplied_consent_expiry_is_refused(expiry):
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.base import canonical_consent_points

    with pytest.raises(ApiError) as exc:
        canonical_consent_points([{"data_point_id": "care", "consent_granted": True, "consent_expiry": expiry}])
    assert exc.value.status == 400 and "consent_expiry" in exc.value.message


def test_record_consent_schema_closes_the_decision_items():
    from dpdpcms_py.validators import validate_payload

    decision = {
        "data_point_id": "care",
        "consent_granted": True,
        "purpose_agreed_to": "Care",
        "timestamp_updated": "2026-10-15T00:00:00Z",
    }
    base = {"_func": "record_consent", "user_id": "u", "policy_id": "p"}
    assert validate_payload({**base, "data_point_consents": [decision]}) == []
    errors = validate_payload({**base, "data_point_consents": [{**decision, "consent_expiry": "2027-01-01"}]})
    assert errors and "consent_expiry" in errors[0]


@pytest.mark.parametrize(
    ("expiry", "granted"),
    [
        ("2000-01-01", False),  # naive and past: lapsed, read as UTC
        ("2999-01-01", True),  # naive and future
        ("2000-01-01T00:00:00+00:00", False),
        ("yesterday", True),  # unparseable: ignored, as before
        (12345, True),
    ],
)
def test_point_granted_never_raises_on_a_stored_expiry(expiry, granted):
    from dpdpcms_py.services.consent import _point_granted

    assert _point_granted({"data_point_id": "care", "consent_granted": True, "consent_expiry": expiry}) is granted


@needs_db
def test_principal_with_a_naive_stored_expiry_can_still_withdraw(tx):
    """P12-01: one naive consent_expiry made withdrawal of EVERY purpose 500."""
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("care", "research"))
        cur.execute(
            "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp,"
            " jurisdiction, language_selected, data_point_consents, is_active_consent, consent_status_general,"
            " consent_mechanism, ip_address, created_at, last_updated_at)"
            " VALUES (uuid_generate_v4(), 'asha', %s, %s, 'v1', NOW(), 'IN', 'en', %s, TRUE, 'CONSENT_GIVEN',"
            " 'WEB', '1.2.3.4', NOW(), NOW())",
            (
                fid,
                pol,
                real_db.as_jsonb(
                    [
                        {"data_point_id": "care", "consent_granted": True, "consent_expiry": "2999-01-01"},
                        {"data_point_id": "research", "consent_granted": True},
                    ]
                ),
            ),
        )
    service = ConsentService()
    assert service.validate_consent(_ctx(fid, {"user_id": "asha", "required_purpose_id": "care"}))["valid"] is True
    service.export_consent_history(_ctx(fid, {"user_id": "asha", "format": "CSV"}))
    service.withdraw_consent(_ctx(fid, {"user_id": "asha", "purpose_ids": ["research"]}))
    assert service.validate_consent(_ctx(fid, {"user_id": "asha", "required_purpose_id": "research"}))["valid"] is False


# ---- P12-03: version precedence follows activation, not drafting ------------------


@needs_db
def test_version_drafted_earlier_but_activated_later_is_the_one_served(tx):
    from dpdpcms_py.services.catalog import PolicyService, served_policy_version

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_policy_version(cur, fid, pol, "v2", "DRAFT")
        _seed_policy_version(cur, fid, pol, "v3", "DRAFT")
        cur.execute(
            "UPDATE consent_policies SET effective_date = NOW() - INTERVAL '10 days' WHERE id = %s AND version = 'v2'",
            (pol,),
        )
        cur.execute(
            "UPDATE consent_policies SET effective_date = NOW() - INTERVAL '5 days' WHERE id = %s AND version = 'v3'",
            (pol,),
        )
    service = PolicyService()
    assert service.publish_policy(_ctx(fid, {"policy_id": pol, "version": "v3"}))["data"]["status"] == "ACTIVE"
    out = service.publish_policy(_ctx(fid, {"policy_id": pol, "version": "v2"}))
    assert out["data"] == {"status": "ACTIVE", "activated_versions": ["v2"]}
    assert served_policy_version(pol, fid) == "v2"
    with tx.cursor() as cur:
        cur.execute("SELECT version, status FROM consent_policies WHERE id = %s AND fiduciary_id = %s", (pol, fid))
        assert {r["version"]: r["status"] for r in cur.fetchall()} == {
            "v1": "ARCHIVED",
            "v2": "ACTIVE",
            "v3": "ARCHIVED",
        }


@needs_db
def test_create_policy_honours_a_future_effective_date(tx):
    from dpdpcms_py.services.catalog import PolicyService, served_policy_version

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
    future = (datetime.now(UTC) + timedelta(days=30)).isoformat()
    content = {
        "en": {
            "title": "P",
            "data_processing_purposes": [{"id": "care", "name": "care", "duration_type": "OPEN_ENDED"}],
        }
    }
    service = PolicyService()
    service.create_policy(
        _ctx(
            fid,
            {
                "policy_id": pol,
                "version": "v2",
                "jurisdiction": "IN",
                "policy_content": content,
                "effective_date": future,
            },
        )
    )
    service.publish_policy(_ctx(fid, {"policy_id": pol, "version": "v2"}))
    # Active but not yet in effect: v1 is still the notice served.
    assert served_policy_version(pol, fid) == "v1"


# ---- P12-04: Board intimation time is the server's -----------------------------------


def _report(fid, **extra):
    from dpdpcms_py.services.compliance import BreachService

    return BreachService().report_breach(
        _ctx(
            fid,
            {
                "title": "Lost laptop",
                "description": "An unencrypted laptop was lost.",
                "actionable_steps": "Watch for phishing calls.",
                **extra,
            },
        )
    )


@needs_db
def test_board_intimation_cannot_be_backdated_or_future_dated(tx):
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.compliance import BreachService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    detected = datetime.now(UTC) - timedelta(days=10)
    breach = _report(fid, detected_at=detected.isoformat())["breach_id"]
    service = BreachService()
    for when in (detected - timedelta(days=10), datetime.now(UTC) + timedelta(days=365)):
        with pytest.raises(ApiError) as exc:
            service.record_board_intimation(
                _ctx(fid, {"id": breach, "board_reference": "DPB-1", "intimated_at": when.isoformat()})
            )
        assert exc.value.status == 400
    out = service.record_board_intimation(
        _ctx(
            fid, {"id": breach, "board_reference": "DPB-1", "intimated_at": (detected + timedelta(hours=1)).isoformat()}
        )
    )
    assert out["late"] is False  # asserted within the 72 hours
    recorded = datetime.fromisoformat(out["board_notified_at"])
    assert abs((recorded - datetime.now(UTC)).total_seconds()) < 120  # server time, not the asserted one
    with tx.cursor() as cur:
        cur.execute("SELECT board_intimated_at_asserted FROM breach_incidents WHERE id = %s", (breach,))
        assert cur.fetchone()["board_intimated_at_asserted"] is not None


@needs_db
def test_board_intimation_without_an_asserted_time_is_late_by_server_clock(tx):
    from dpdpcms_py.services.compliance import BreachService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    breach = _report(fid, detected_at=(datetime.now(UTC) - timedelta(days=10)).isoformat())["breach_id"]
    out = BreachService().record_board_intimation(_ctx(fid, {"id": breach, "board_reference": "DPB-2"}))
    assert out["late"] is True and out["intimated_at_asserted"] is None


@needs_db
def test_future_detection_is_refused(tx):
    from dpdpcms_py.errors import ApiError

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    with pytest.raises(ApiError) as exc:
        _report(fid, detected_at=(datetime.now(UTC) + timedelta(days=1)).isoformat())
    assert exc.value.status == 400


# ---- Rule 7 contents and the P12-12 PDF -------------------------------------------------


@needs_db
def test_breach_report_is_a_real_pdf_with_the_rule7_contents(tx):
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.compliance import BreachService, breach_report_lines

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    breach = _report(
        fid,
        likely_consequences="Phishing attempts",
        mitigation_measures="Remote wipe issued",
        contact_point="dpo@example.org",
    )["breach_id"]
    service = BreachService()
    with pytest.raises(ApiError) as exc:  # Rule 7(2)(b) needs every field
        service.update_breach_status(_ctx(fid, {"id": breach, "status": "CONTAINED", "submit_detailed_report": True}))
    assert exc.value.status == 400
    service.update_breach_status(
        _ctx(
            fid,
            {
                "id": breach,
                "status": "CONTAINED",
                "circumstances": "Left in a taxi",
                "cause_findings": "Staff member did not use the locker",
                "remedial_measures": "Disk encryption enforced",
                "submit_detailed_report": True,
            },
        )
    )
    pdf = service.download_breach_report(_ctx(fid, {"id": breach}))
    assert isinstance(pdf, bytes) and pdf.startswith(b"%PDF")
    row = service._breach_row(_ctx(fid, {"id": breach}))
    lines = "\n".join(breach_report_lines(row))
    for text in ("Phishing attempts", "Remote wipe issued", "dpo@example.org", "Left in a taxi", "Disk encryption"):
        assert text in lines
    assert row["board_report_submitted_at"] is not None


def test_breach_pdf_is_served_under_its_own_name():
    from dpdpcms_py import main

    response = main._json_response(b"%PDF-1.4", func="download_breach_report")
    assert response.media_type == "application/pdf"
    assert 'filename="breach-report.pdf"' in response.headers["content-disposition"]


# ---- P12-05: a tenant reader cannot pick its own tenant ---------------------------------


@needs_db
def test_tenant_reader_cannot_steer_rls_with_a_session_setting(tx):
    with tx.cursor() as cur:
        fid_a, pol_a = _seed_tenant(cur)
        _seed_consent(cur, fid_a, pol_a, "asha")
        cur.execute("SET LOCAL ROLE tsi_tenant_reader")
        cur.execute("SELECT set_config('tsi.fiduciary_id', %s, true)", (fid_a,))
        cur.execute("SELECT COUNT(*) AS n FROM consent_records WHERE fiduciary_id = %s", (fid_a,))
        assert cur.fetchone()["n"] == 0
        cur.execute("RESET ROLE")


@needs_db
def test_tenant_reader_cannot_read_or_write_its_mapping(tx):
    import psycopg

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute("SET LOCAL ROLE tsi_tenant_reader")
        for sql, params in (
            ("SELECT * FROM tsi_reader_tenants", ()),
            ("INSERT INTO tsi_reader_tenants (role_name, tenant_id) VALUES ('tsi_tenant_reader', %s)", (fid,)),
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege), tx.transaction():
                cur.execute(sql, params)
        cur.execute("RESET ROLE")


# ---- P12-06: policy ids are per tenant; duplicates are 409 ---------------------------


@needs_db
def test_two_tenants_may_use_the_same_policy_id(tx):
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.catalog import PolicyService

    with tx.cursor() as cur:
        fid_a, pol = _seed_tenant(cur)
        fid_b, _ = _seed_tenant(cur)
    content = {
        "en": {
            "title": "P",
            "data_processing_purposes": [{"id": "care", "name": "care", "duration_type": "OPEN_ENDED"}],
        }
    }
    payload = {"policy_id": pol, "version": "v1", "jurisdiction": "IN", "policy_content": content}
    assert PolicyService().create_policy(_ctx(fid_b, payload))["success"] is True
    with pytest.raises(ApiError) as exc:
        PolicyService().create_policy(_ctx(fid_a, payload))
    assert exc.value.status == 409


def test_unique_violation_maps_to_409(monkeypatch):
    import psycopg
    from dpdpcms_py import main
    from fastapi.testclient import TestClient

    def boom(*args, **kwargs):
        raise psycopg.errors.UniqueViolation("duplicate key value")

    monkeypatch.setattr(main, "validate_payload", lambda payload: [])
    monkeypatch.setattr(main, "api_key_valid", lambda key, secret: (True, "f", {"WRITE", "READ"}, None))
    monkeypatch.setattr(main.SERVICE_REGISTRY["consent"], "handle", boom)
    response = TestClient(main.app).post(
        "/api/v1/client/consent",
        json={"_func": "record_consent", "user_id": "u", "policy_id": "p", "data_point_consents": []},
        headers={"X-API-Key": "k", "X-API-Secret": "s"},
    )
    assert response.status_code == 409


# ---- P12-07: legacy text is taken back out of live templates -----------------------------


@needs_db
def test_db29_removes_languages_db27_filled_from_legacy_text(tx):
    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO notification_message_templates_archive (fiduciary_id, notification_type, messages, migrated_to)"
            " VALUES (%s, 'PURGE_ONHOLD_NOTIFICATION', %s, 'ERASURE_REQUESTED_NOTIFICATION')",
            (fid, real_db.as_jsonb({"hi": "on hold", "ta": "on hold ta"})),
        )
        cur.execute(
            "INSERT INTO notification_message_templates (fiduciary_id, notification_type, messages) VALUES (%s, %s, %s)"
            " ON CONFLICT (fiduciary_id, notification_type) DO UPDATE SET messages = EXCLUDED.messages",
            # en is the DPO's own; hi was filled by db/27; ta was since edited by the DPO.
            (fid, "ERASURE_REQUESTED_NOTIFICATION", real_db.as_jsonb({"en": "ack", "hi": "on hold", "ta": "edited"})),
        )
        cur.execute((REPO / "db" / "29_p12_remediation.sql").read_text(encoding="utf-8"))
        cur.execute(
            "SELECT messages FROM notification_message_templates WHERE fiduciary_id = %s"
            " AND notification_type = 'ERASURE_REQUESTED_NOTIFICATION'",
            (fid,),
        )
        assert cur.fetchone()["messages"] == {"en": "ack", "ta": "edited"}


@needs_db
def test_archived_legacy_text_is_shown_beside_its_live_type(tx):
    from dpdpcms_py.services.governance import NotificationService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO notification_message_templates_archive (fiduciary_id, notification_type, messages, migrated_to)"
            " VALUES (%s, 'EXPIRY_NOTIFICATION', %s, 'PURPOSE_CLOSED')",
            (fid, real_db.as_jsonb({"en": "legacy expiry"})),
        )
    rows = NotificationService().get_notification_messages(_ctx(fid, {"fiduciary_id": fid}))
    closed = [r for r in rows if r["notification_type"] == "PURPOSE_CLOSED"]
    assert closed and closed[0]["archived_legacy"][0]["messages"] == {"en": "legacy expiry"}


# ---- P12-09: health endpoints disclose status only ------------------------------------------


@needs_db
def test_worker_health_detail_needs_the_health_token(tx, monkeypatch):
    import asyncio

    from dpdpcms_py import main, worker

    worker.record_heartbeat({"delivery": {"error": "boom"}})

    def call(headers):
        response = asyncio.run(main.healthz_worker(SimpleNamespace(headers=headers)))
        return json.loads(response.body)

    assert call({}) == {"status": "degraded"}
    monkeypatch.setattr(main.settings.__class__, "healthz_token", "t" * 32, raising=False)
    object.__setattr__(main.settings, "healthz_token", "t" * 32)
    try:
        assert call({"x-health-token": "wrong"}) == {"status": "degraded"}
        detail = call({"x-health-token": "t" * 32})
        assert detail["status"] == "degraded" and detail["failed_sweeps"] == ["delivery"]
    finally:
        object.__setattr__(main.settings, "healthz_token", "")


def test_healthz_never_returns_exception_text(monkeypatch):
    import asyncio
    import contextlib

    from dpdpcms_py import main

    @contextlib.contextmanager
    def broken():
        raise RuntimeError("password authentication failed for user tsi_admin at db.internal")
        yield

    monkeypatch.setattr(main.db, "connection", broken)
    response = asyncio.run(main.healthz())
    assert response.status_code == 503 and json.loads(response.body) == {"status": "unavailable"}


# ---- P12-10: the history filter resolves aliases as the gate does ----------------------------


@needs_db
def test_history_purpose_filter_skips_an_empty_data_point_id(tx):
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("research",))
        cur.execute(
            "INSERT INTO consent_records (id, user_id, fiduciary_id, policy_id, policy_version, timestamp,"
            " jurisdiction, language_selected, data_point_consents, is_active_consent, consent_status_general,"
            " consent_mechanism, ip_address, created_at, last_updated_at)"
            " VALUES (uuid_generate_v4(), 'asha', %s, %s, 'v1', NOW(), 'IN', 'en', %s, TRUE, 'CONSENT_GIVEN',"
            " 'WEB', '1.2.3.4', NOW(), NOW())",
            (fid, pol, real_db.as_jsonb([{"data_point_id": "", "purpose_id": "research", "consent_granted": True}])),
        )
    rows = ConsentService().list_consent_history(_ctx(fid, {"user_id": "asha", "purpose_id": "Research"}))
    assert len(rows) == 1


# ---- P12-11: the outbound allowlist fails closed outside local ------------------------------


def test_empty_allowlist_refuses_to_start_outside_local(monkeypatch):
    from dpdpcms_py import config

    monkeypatch.setenv("OUTBOUND_ALLOWED_HOSTS", "")
    assert config._outbound_allowed_hosts("local") == ()
    with pytest.raises(RuntimeError, match="OUTBOUND_ALLOWED_HOSTS"):
        config._outbound_allowed_hosts("production")
    monkeypatch.setenv("OUTBOUND_ALLOWED_HOSTS", "*")
    assert config._outbound_allowed_hosts("production") == ("*",)


def test_wildcard_allowlist_is_explicitly_unrestricted():
    from dpdpcms_py.netutil import outbound_host_allowed

    assert outbound_host_allowed("anything.example.com", ("*",))
    assert not outbound_host_allowed("anything.example.com", ("hooks.example.in",))


def test_preflight_checks_every_recent_migration():
    script = (REPO / "scripts" / "local" / "shell_scripts" / "preflight.sh").read_text(encoding="utf-8")
    for name in ("27_p11_remediation.sql", "28_security_coverage.sql", "29_p12_remediation.sql"):
        assert name in script


# ---- INV-07: completion only through the evidenced path --------------------------------------


@needs_db
@pytest.mark.parametrize("status", ["PURGE_COMPLETED", "COMPLETED"])
def test_update_purge_status_cannot_complete_a_purge(tx, status):
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.compliance import ComplianceService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        request_id = _seed_purge(cur, fid, "asha", "care")
    with pytest.raises(ApiError) as exc:
        ComplianceService().update_purge_status(_ctx(fid, {"id": request_id, "status": status, "details": "done"}))
    assert exc.value.status == 400
    with tx.cursor() as cur:
        cur.execute("SELECT status FROM purge_requests WHERE id = %s", (request_id,))
        assert cur.fetchone()["status"] == "PENDING"


@needs_db
def test_a_completed_purge_is_not_completed_again(tx):
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.compliance import ComplianceService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        request_id = _seed_purge(cur, fid, "asha", "care")
    payload = {
        "purge_request_id": request_id,
        "status": "PURGE_COMPLETED",
        "records_affected_count": 1,
        "confirmed_by_entity_id": "dpo@example.org",
    }
    ComplianceService().confirm_purge_status(_ctx(fid, dict(payload)))
    with pytest.raises(ApiError) as exc:
        ComplianceService().confirm_purge_status(_ctx(fid, dict(payload)))
    assert exc.value.status == 409


# ---- INV-08: deactivation stops the keys ----------------------------------------------------


@needs_db
@pytest.mark.parametrize("deactivate", ["app", "fiduciary"])
def test_deactivation_revokes_api_keys(tx, deactivate):
    from dpdpcms_py.security import api_key_valid
    from dpdpcms_py.services.catalog import AppService, FiduciaryService
    from dpdpcms_py.services.governance import ApiKeyService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO apps (fiduciary_id, name, status, dpa_reference) VALUES (%s, 'lab', 'ACTIVE', 'DPA-1')"
            " RETURNING id",
            (fid,),
        )
        app = str(cur.fetchone()["id"])
    key = ApiKeyService().generate_api_key(_ctx(fid, {"fiduciary_id": fid, "app_id": app}))["data"]
    assert api_key_valid(key["key_id"], key["raw_api_key"])[0] is True
    if deactivate == "app":
        out = AppService().delete_app(_ctx(fid, {"app_id": app}))
    else:
        out = FiduciaryService().delete_fiduciary(_ctx(None, {"fiduciary_id": fid}))
    assert out["api_keys_revoked"] == 1
    assert api_key_valid(key["key_id"], key["raw_api_key"])[0] is False


@needs_db
def test_key_of_an_inactive_app_fails_even_if_not_revoked(tx):
    """INV-08 defence in depth: an app set INACTIVE by any other path."""
    from dpdpcms_py.security import api_key_valid
    from dpdpcms_py.services.governance import ApiKeyService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute(
            "INSERT INTO apps (fiduciary_id, name, status, dpa_reference) VALUES (%s, 'lab', 'ACTIVE', 'DPA-1')"
            " RETURNING id",
            (fid,),
        )
        app = str(cur.fetchone()["id"])
    key = ApiKeyService().generate_api_key(_ctx(fid, {"fiduciary_id": fid, "app_id": app}))["data"]
    with tx.cursor() as cur:
        cur.execute("UPDATE apps SET status = 'INACTIVE' WHERE id = %s", (app,))
    assert api_key_valid(key["key_id"], key["raw_api_key"])[0] is False


# ---- P12-08: no inline script anywhere, and the CSP says so ----------------------------------


def test_csp_allows_only_same_origin_script():
    from dpdpcms_py.main import CONTENT_SECURITY_POLICY

    directives = dict(d.strip().split(" ", 1) for d in CONTENT_SECURITY_POLICY.split(";"))
    assert directives["script-src"] == "'self'"
    assert directives["script-src-attr"] == "'none'"
    assert "cdnjs" not in CONTENT_SECURITY_POLICY and "cdn.tailwindcss.com" not in CONTENT_SECURITY_POLICY


def test_web_pages_carry_no_inline_script_or_handler():
    import re

    from dpdpcms_py.config import WEB_ROOT

    handler = re.compile(r"<[^>]*\son[a-z]+\s*=", re.IGNORECASE | re.DOTALL)
    for page in WEB_ROOT.rglob("*.html"):
        text = page.read_text(encoding="utf-8")
        for tag in re.findall(r"<script\b[^>]*>", text, re.IGNORECASE):
            assert "src=" in tag, f"{page}: inline <script>"
            assert "https://" not in tag, f"{page}: third-party script {tag}"
        assert not handler.search(text), f"{page}: inline event handler"
        assert "javascript:" not in text, f"{page}: javascript: URL"
    for script in WEB_ROOT.rglob("*.js"):
        if "vendor" in script.parts:
            continue
        text = script.read_text(encoding="utf-8")
        assert not re.search(r"<[a-z][^>`]*\son(click|change|submit|input|load|error)\s*=", text), script


# ---- Security Coverage: R6-a clear-text contacts, R6-c audit reads ---------------------------


@needs_db
def test_contact_details_are_stored_encrypted_only(tx):
    from dpdpcms_py.services.catalog import AppService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    out = AppService().create_app(
        _ctx(fid, {"fiduciary_id": fid, "name": "lab", "email": "lab@example.org", "phone": "+911234567890"})
    )
    with tx.cursor() as cur:
        cur.execute(
            "SELECT email_plaintext, phone_plaintext, email_enc IS NOT NULL AS enc FROM apps WHERE id = %s",
            (out["app_id"],),
        )
        row = cur.fetchone()
    assert row["email_plaintext"] is None and row["phone_plaintext"] is None and row["enc"]


@needs_db
def test_reading_the_audit_ledger_is_itself_audited_and_capped(tx):
    from dpdpcms_py.audit import AUDIT_READ_MAX
    from dpdpcms_py.services.governance import ACCESS_REPORT_ACTIONS, AuditService

    assert {"PRINCIPAL_LOGIN_SUCCESS", "PRINCIPAL_LOGIN_FAILURE", "AUDIT_LOG_READ"} <= ACCESS_REPORT_ACTIONS
    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    ctx = _ctx(fid, {"fiduciary_id": fid, "limit": 10_000_000})
    AuditService().list_audit_logs(ctx)
    with tx.cursor() as cur:
        cur.execute(
            "SELECT context_details FROM audit_logs WHERE fiduciary_id = %s AND audit_action = 'AUDIT_LOG_READ'",
            (fid,),
        )
        rows = cur.fetchall()
    assert len(rows) == 1
    assert AUDIT_READ_MAX == 5000


def test_lockfile_pins_every_direct_requirement_with_hashes():
    import re

    lock = (REPO / "python_port" / "requirements.lock").read_text(encoding="utf-8")
    pinned = {m.group(1).lower() for m in re.finditer(r"^([A-Za-z0-9_.-]+)==", lock, re.M)}
    reqs = (REPO / "python_port" / "requirements.txt").read_text(encoding="utf-8").splitlines()
    direct = {re.split(r"[\[<>=;# ]", line.strip())[0].lower() for line in reqs if line.strip()}
    assert direct <= pinned
    assert lock.count("--hash=sha256:") >= len(pinned)
    docker = (REPO / "python_port" / "Dockerfile").read_text(encoding="utf-8")
    assert "--require-hashes -r /app/python_port/requirements.lock" in docker
