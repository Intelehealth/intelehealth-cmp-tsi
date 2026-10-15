"""Security Coverage sheet (workbook v9) regressions.

DB-backed tests reuse the transaction-per-test fixture of test_integration_db
and skip without a live Postgres; the rest are pure unit tests.
"""

import json
from types import SimpleNamespace

import pytest
from tests.test_integration_db import (
    _DB_READY,
    REPO,
    _ctx,
    _seed_consent,
    _seed_tenant,
)

needs_db = pytest.mark.skipif(not _DB_READY, reason="no live Postgres configured")


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


# ---- S8-6: breach intimation --------------------------------------------------


@needs_db
def test_reporting_a_breach_notifies_the_principals_it_names(tx):
    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    out = _report(fid, affected_user_ids=["asha", "ravi"], affected_user_ids_csv="user_id\nravi\nmeena\n")
    assert out["notified"] == 3 and out["affected_principal_count"] == 3
    with tx.cursor() as cur:
        cur.execute(
            "SELECT recipient_id, notification_type, context FROM notifications WHERE fiduciary_id = %s"
            " AND recipient_type = 'PRINCIPAL' ORDER BY recipient_id",
            (fid,),
        )
        rows = cur.fetchall()
    assert [r["recipient_id"] for r in rows] == ["asha", "meena", "ravi"]
    assert all(r["notification_type"] == "BREACH_NOTIFICATION" for r in rows)
    assert rows[0]["context"]["actionable_steps"] == "Watch for phishing calls."


@needs_db
def test_breach_under_a_purpose_notifies_its_holders_once(tx):
    from dpdpcms_py.services.compliance import BreachService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("care", "research"))
        _seed_consent(cur, fid, pol, "asha", purposes=("care",))
        _seed_consent(cur, fid, pol, "ravi", purposes=("research",))
    out = _report(fid, affected_purpose_id="CARE", breach_category="phishing")
    assert out["notified"] == 1
    again = BreachService().notify_affected_principals(_ctx(fid, {"id": out["breach_id"]}))
    assert again["notified"] == 0 and again["affected_total"] == 1
    with tx.cursor() as cur:
        cur.execute("SELECT notification_type FROM breach_incidents WHERE id = %s", (out["breach_id"],))
        assert cur.fetchone()["notification_type"] == "BREACH_NOTIFICATION_PHISHING"


@needs_db
def test_board_intimation_is_recorded_once_and_stops_the_clock(tx):
    from dpdpcms_py import jobs
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.compliance import BreachService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    late = _report(fid, detected_at="2020-01-01T00:00:00Z")
    due = _report(fid, detected_at=None)
    with tx.cursor() as cur:
        cur.execute(
            "UPDATE breach_incidents SET board_notification_deadline = NOW() + INTERVAL '2 hours' WHERE id = %s",
            (due["breach_id"],),
        )
    assert jobs.flag_breach_board_deadlines()["alerted"] >= 2
    assert jobs.flag_breach_board_deadlines()["alerted"] == 0  # once per breach per stage
    with tx.cursor() as cur:
        cur.execute(
            "SELECT alert_type, event_ref_id FROM alerts WHERE fiduciary_id = %s AND alert_type LIKE 'BREACH_BOARD%%'",
            (fid,),
        )
        alerts = {r["event_ref_id"]: r["alert_type"] for r in cur.fetchall()}
    assert alerts == {late["breach_id"]: "BREACH_BOARD_DEADLINE_MISSED", due["breach_id"]: "BREACH_BOARD_DEADLINE_DUE"}

    with pytest.raises(ApiError):
        BreachService().record_board_intimation(_ctx(fid, {"id": late["breach_id"]}))  # reference is required
    out = BreachService().record_board_intimation(_ctx(fid, {"id": late["breach_id"], "board_reference": "DPB-1"}))
    assert out["late"] is True
    with pytest.raises(ApiError) as exc:
        BreachService().record_board_intimation(_ctx(fid, {"id": late["breach_id"], "board_reference": "DPB-2"}))
    assert exc.value.status == 409


@needs_db
def test_another_tenant_cannot_record_an_intimation(tx):
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.compliance import BreachService

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        other, _ = _seed_tenant(cur)
    breach = _report(fid)
    with pytest.raises(ApiError) as exc:
        BreachService().record_board_intimation(_ctx(other, {"id": breach["breach_id"], "board_reference": "X"}))
    assert exc.value.status == 404


# ---- R6-d: worker heartbeat -----------------------------------------------------


@needs_db
def test_worker_health_reports_stale_and_failed_sweeps(tx):
    import asyncio

    from dpdpcms_py import main, worker

    def status(headers=None):
        request = SimpleNamespace(headers=headers or {})
        response = asyncio.run(main.healthz_worker(request))
        return response.status_code, json.loads(response.body)

    with tx.cursor() as cur:
        cur.execute("DELETE FROM worker_heartbeat")
    assert status()[0] == 503
    worker.record_heartbeat({"delivery": {"sent": 1}})
    code, body = status()
    assert code == 200 and body == {"status": "ok"}  # P12-09: status only
    worker.record_heartbeat({"delivery": {"error": "boom"}})
    code, body = status()
    assert code == 503 and body == {"status": "degraded"}
    with tx.cursor() as cur:
        cur.execute("UPDATE worker_heartbeat SET failed_sweeps = '[]', last_cycle_at = NOW() - INTERVAL '2 hours'")
    assert status()[0] == 503


# ---- R6-b: row-level security for non-application roles --------------------------


@needs_db
def test_tenant_reader_role_sees_only_its_own_tenant(tx):
    with tx.cursor() as cur:
        fid_a, pol_a = _seed_tenant(cur)
        fid_b, pol_b = _seed_tenant(cur)
        _seed_consent(cur, fid_a, pol_a, "asha")
        _seed_consent(cur, fid_b, pol_b, "ravi")
        # P12-05: the mapping lives in an application-owned table.
        cur.execute("INSERT INTO tsi_reader_tenants (role_name, tenant_id) VALUES ('tsi_tenant_reader', %s)", (fid_a,))
        cur.execute("SET LOCAL ROLE tsi_tenant_reader")
        cur.execute("SELECT DISTINCT fiduciary_id::text AS f FROM consent_records")
        assert [r["f"] for r in cur.fetchall()] == [fid_a]
        cur.execute("SELECT COUNT(*) AS n FROM audit_logs WHERE fiduciary_id::text = %s", (fid_b,))
        assert cur.fetchone()["n"] == 0
        cur.execute("RESET ROLE")
        # The application (table owner) is unaffected.
        cur.execute(
            "SELECT COUNT(DISTINCT fiduciary_id) AS n FROM consent_records WHERE fiduciary_id IN (%s, %s)",
            (fid_a, fid_b),
        )
        assert cur.fetchone()["n"] == 2


# ---- R14: approved outbound destinations -------------------------------------------


def test_outbound_allowlist_matches_hosts_and_subdomains():
    from dpdpcms_py.netutil import outbound_host_allowed

    assert outbound_host_allowed("anything.example.com", ())
    allowed = ("hooks.example.in", ".gov.in")
    assert outbound_host_allowed("hooks.example.in", allowed)
    assert outbound_host_allowed("a.hooks.example.in", allowed)
    assert outbound_host_allowed("sms.nic.gov.in.", allowed)
    assert not outbound_host_allowed("evilhooks.example.in", allowed)
    assert not outbound_host_allowed("hooks.example.in.attacker.com", allowed)


def test_webhook_url_outside_the_allowlist_is_refused(monkeypatch):
    from dpdpcms_py import netutil

    monkeypatch.setattr(netutil, "resolve_public", lambda host: "203.0.113.10")
    monkeypatch.setattr(
        netutil, "outbound_host_allowed", lambda host, allowed=("hooks.example.in",): host.endswith("example.in")
    )
    assert netutil.validate_outbound_url("https://hooks.example.in/x") == "https://hooks.example.in/x"
    with pytest.raises(ValueError, match="approved outbound destination"):
        netutil.validate_outbound_url("https://hooks.example.com/x")


# ---- M-03 / M-02: transport hardening and supply chain -----------------------------


def test_responses_carry_a_content_security_policy():
    from dpdpcms_py.main import app
    from fastapi.testclient import TestClient

    response = TestClient(app).get("/healthz")
    csp = response.headers["Content-Security-Policy"]
    for directive in ("frame-ancestors 'none'", "object-src 'none'", "base-uri 'self'", "default-src 'self'"):
        assert directive in csp
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_ci_audits_dependencies():
    workflow = (REPO / ".github" / "workflows" / "main.yml").read_text(encoding="utf-8")
    assert "pip-audit" in workflow and "requirements.txt" in workflow


# ---- P11-10: client readers (static, no database) ---------------------------------


def test_client_readers_resolve_aliases_in_the_server_order():
    """P11-10: the record-detail modal and the wallet read id before purpose_id."""
    portal = (REPO / "web" / "rights" / "portal.js").read_text(encoding="utf-8")
    # P12-08: each page's script now lives in its own file.
    dashboard = (REPO / "web" / "rights" / "dashboard.js").read_text(encoding="utf-8")
    wallet = (REPO / "web" / "tour" / "dpdp-wallet.js").read_text(encoding="utf-8")
    order = "['data_point_id', 'purpose_id', 'id']"
    assert order in portal and order in wallet
    for page in (dashboard, wallet):
        assert "item.data_point_id || item.id" not in page
        assert "c.data_point_id || c.id," not in page
        assert "consent_granted === true" not in page
