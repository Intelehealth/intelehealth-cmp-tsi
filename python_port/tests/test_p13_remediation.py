"""Workbook v11 (P13-01..05) regressions.

DB-backed tests reuse the transaction-per-test fixture and seed helpers of
test_integration_db.py and skip without a live Postgres; the rest are unit
tests.
"""

import importlib.util
import re
from datetime import UTC, date, datetime, timedelta

import pytest
from tests.test_integration_db import (
    _DB_READY,
    REPO,
    _ctx,
    _seed_consent,
    _seed_tenant,
)

needs_db = pytest.mark.skipif(not _DB_READY, reason="no live Postgres configured")


def _admin_ctx(payload):
    """A global ADMIN: no tenant of its own, so it must name one."""
    from dpdpcms_py.context import RequestContext

    return RequestContext(
        path="/api/v1/admin/policy",
        category="admin",
        service="policy",
        payload=payload,
        headers={},
        fiduciary_id=None,
        auth_token={"email": "admin@example.org", "role": "ADMIN"},
    )


def _policy_rows(cur, pol):
    cur.execute("SELECT fiduciary_id::text AS fid, version, status FROM consent_policies WHERE id = %s", (pol,))
    return {(row["fid"], row["version"]): row["status"] for row in cur.fetchall()}


def _same_id_in_two_tenants(cur):
    fid_a, pol = _seed_tenant(cur)
    fid_b, _ = _seed_tenant(cur)
    cur.execute(
        "INSERT INTO consent_policies (id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content)"
        " SELECT id, version, %s, effective_date, status, jurisdiction, policy_content"
        " FROM consent_policies WHERE id = %s AND fiduciary_id = %s",
        (fid_b, pol, fid_a),
    )
    return fid_a, fid_b, pol


# ---- P13-01: a global ADMIN's policy operations stay in the tenant it names ----------


@needs_db
def test_admin_get_policy_returns_the_named_tenants_row(tx):
    from dpdpcms_py.services.catalog import PolicyService

    with tx.cursor() as cur:
        fid_a, fid_b, pol = _same_id_in_two_tenants(cur)
    for fid in (fid_a, fid_b):
        out = PolicyService().get_policy(_admin_ctx({"policy_id": pol, "version": "v1", "fiduciary_id": fid}))
        assert str(out["fiduciary_id"]) == fid


@needs_db
def test_admin_delete_policy_archives_only_the_named_tenants_policy(tx):
    from dpdpcms_py.services.catalog import PolicyService

    with tx.cursor() as cur:
        fid_a, fid_b, pol = _same_id_in_two_tenants(cur)
    PolicyService().delete_policy(_admin_ctx({"policy_id": pol, "fiduciary_id": fid_b}))
    with tx.cursor() as cur:
        rows = _policy_rows(cur, pol)
    assert rows[(fid_b, "v1")] == "ARCHIVED"
    assert rows[(fid_a, "v1")] == "ACTIVE"  # A keeps its served notice


@needs_db
def test_admin_update_and_publish_policy_touch_only_the_named_tenant(tx):
    from dpdpcms_py.services.catalog import PolicyService

    with tx.cursor() as cur:
        fid_a, fid_b, pol = _same_id_in_two_tenants(cur)
        for fid in (fid_a, fid_b):
            cur.execute(
                "INSERT INTO consent_policies (id, version, fiduciary_id, effective_date, status, jurisdiction, policy_content)"
                " SELECT id, 'v2', fiduciary_id, NOW(), 'DRAFT', jurisdiction, policy_content"
                " FROM consent_policies WHERE id = %s AND fiduciary_id = %s AND version = 'v1'",
                (pol, fid),
            )
    content = {
        "en": {
            "title": "Changed",
            "data_processing_purposes": [{"id": "care", "name": "care", "duration_type": "OPEN_ENDED"}],
        }
    }
    service = PolicyService()
    service.update_policy(
        _admin_ctx({"policy_id": pol, "version": "v2", "fiduciary_id": fid_b, "policy_content": content})
    )
    with tx.cursor() as cur:
        cur.execute(
            "SELECT fiduciary_id::text AS fid, policy_content->'en'->>'title' AS title FROM consent_policies"
            " WHERE id = %s AND version = 'v2'",
            (pol,),
        )
        titles = {row["fid"]: row["title"] for row in cur.fetchall()}
    assert titles == {fid_a: "P", fid_b: "Changed"}

    service.publish_policy(_admin_ctx({"policy_id": pol, "version": "v2", "fiduciary_id": fid_b}))
    with tx.cursor() as cur:
        rows = _policy_rows(cur, pol)
    assert rows[(fid_a, "v2")] == "DRAFT" and rows[(fid_a, "v1")] == "ACTIVE"
    assert rows[(fid_b, "v2")] != "DRAFT"


@needs_db
@pytest.mark.parametrize("func", ["get_policy", "update_policy", "publish_policy", "delete_policy"])
def test_admin_policy_operation_without_a_tenant_is_refused(tx, func):
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.catalog import PolicyService

    with tx.cursor() as cur:
        _, _, pol = _same_id_in_two_tenants(cur)
    payload = {"policy_id": pol, "version": "v1"}
    if func == "update_policy":
        payload["policy_content"] = {
            "en": {
                "title": "P",
                "data_processing_purposes": [{"id": "care", "name": "care", "duration_type": "OPEN_ENDED"}],
            }
        }
    with pytest.raises(ApiError) as exc:
        getattr(PolicyService(), func)(_admin_ctx(payload))
    assert exc.value.status == 400 and "fiduciary_id" in exc.value.message
    with tx.cursor() as cur:
        assert set(_policy_rows(cur, pol).values()) == {"ACTIVE"}


@needs_db
def test_tenant_bound_caller_cannot_reach_another_tenants_policy_by_naming_it(tx):
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.catalog import PolicyService

    with tx.cursor() as cur:
        fid_a, fid_b, pol = _same_id_in_two_tenants(cur)
    out = PolicyService().get_policy(_ctx(fid_a, {"policy_id": pol, "version": "v1", "fiduciary_id": fid_b}))
    assert str(out["fiduciary_id"]) == fid_a
    PolicyService().delete_policy(_ctx(fid_a, {"policy_id": pol, "fiduciary_id": fid_b}))
    with tx.cursor() as cur:
        rows = _policy_rows(cur, pol)
    assert rows[(fid_a, "v1")] == "ARCHIVED" and rows[(fid_b, "v1")] == "ACTIVE"
    with pytest.raises(ApiError):
        PolicyService().get_policy(_ctx(fid_a, {"policy_id": "missing", "version": "v1"}))


def test_console_names_the_tenant_on_every_policy_write():
    script = (REPO / "web" / "console" / "dpo" / "policies.js").read_text(encoding="utf-8")
    assert '"fiduciary_id": (isEditing && editingFiduciaryId)' in script
    assert "const fidId = payload.fiduciary_id;" in script


# ---- P13-02: 'late' is judged on the recorded time ------------------------------------


@needs_db
def test_asserted_time_cannot_turn_a_late_intimation_on_time(tx):
    from dpdpcms_py.services.compliance import BreachService
    from tests.test_p12_remediation import _report

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    detected = datetime.now(UTC) - timedelta(days=10)
    breach = _report(fid, detected_at=detected.isoformat())["breach_id"]
    out = BreachService().record_board_intimation(
        _ctx(
            fid, {"id": breach, "board_reference": "DPB-9", "intimated_at": (detected + timedelta(hours=1)).isoformat()}
        )
    )
    assert out["late"] is True
    assert out["late_as_asserted"] is False


@needs_db
def test_on_time_intimation_is_not_late(tx):
    from dpdpcms_py.services.compliance import BreachService
    from tests.test_p12_remediation import _report

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    breach = _report(fid, detected_at=(datetime.now(UTC) - timedelta(hours=2)).isoformat())["breach_id"]
    out = BreachService().record_board_intimation(_ctx(fid, {"id": breach, "board_reference": "DPB-10"}))
    assert out["late"] is False and out["late_as_asserted"] is None


def test_breach_pdf_judges_late_on_the_recorded_time():
    from dpdpcms_py.services.compliance import breach_report_lines

    deadline = datetime(2026, 10, 1, tzinfo=UTC)
    lines = breach_report_lines(
        {
            "id": "b-1",
            "board_notification_deadline": deadline,
            "board_notified_at": deadline + timedelta(days=7),
            "board_intimated_at_asserted": deadline - timedelta(hours=60),
        }
    )
    assert "Late (by the recorded time): yes" in lines
    assert "Late by the DPO's asserted time (unverified): no" in lines


# ---- P13-03: the RLS helper is no longer a mapping oracle -----------------------------


@needs_db
def test_tenant_reader_sees_its_mapped_tenant_through_the_view(tx):
    with tx.cursor() as cur:
        fid_a, pol_a = _seed_tenant(cur)
        fid_b, pol_b = _seed_tenant(cur)
        _seed_consent(cur, fid_a, pol_a, "asha")
        _seed_consent(cur, fid_b, pol_b, "ravi")
        cur.execute(
            "INSERT INTO tsi_reader_tenants (role_name, tenant_id) VALUES ('tsi_tenant_reader', %s)"
            " ON CONFLICT DO NOTHING",
            (fid_b,),
        )
        cur.execute("INSERT INTO tsi_reader_tenants (role_name, tenant_id) VALUES ('someone_else', %s)", (fid_a,))
        cur.execute("SET LOCAL ROLE tsi_tenant_reader")
        cur.execute(
            "SELECT fiduciary_id::text AS fid, COUNT(*) AS n FROM consent_records"
            " WHERE fiduciary_id IN (%s, %s) GROUP BY 1",
            (fid_a, fid_b),
        )
        assert {row["fid"]: row["n"] for row in cur.fetchall()} == {fid_b: 1}
        cur.execute("SELECT tenant_id::text AS t FROM tsi_reader_my_tenants")
        seen = {row["t"] for row in cur.fetchall()}
        assert fid_b in seen and fid_a not in seen  # someone_else's mapping is invisible
        cur.execute("RESET ROLE")


@needs_db
def test_mapping_oracle_function_is_gone(tx):
    import psycopg

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        cur.execute("SET LOCAL ROLE tsi_tenant_reader")
        with pytest.raises(psycopg.errors.UndefinedFunction), tx.transaction():
            cur.execute("SELECT tsi_reader_may_see('someone_else', %s)", (fid,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege), tx.transaction():
            cur.execute("SELECT * FROM tsi_reader_tenants")
        cur.execute("RESET ROLE")


def test_db30_is_registered_everywhere_migrations_are_listed():
    sql = (REPO / "db" / "30_p13_remediation.sql").read_text(encoding="utf-8")
    assert "security_barrier" in sql and "DROP FUNCTION IF EXISTS tsi_reader_may_see" in sql
    for path in (
        REPO / "scripts" / "local" / "shell_scripts" / "preflight.sh",
        REPO / "scripts" / "local" / "shell_scripts" / "common.sh",
        REPO / "README.md",
    ):
        assert "30_p13_remediation.sql" in path.read_text(encoding="utf-8"), path


# ---- P13-04: the schema says what the server enforces ---------------------------------


@pytest.mark.parametrize("func", ["record_consent", "request_reconsent"])
def test_language_enum_in_schema_matches_the_server_list(func):
    import json

    from dpdpcms_py.defaults import NOTIFICATION_LANGUAGES

    schema = json.loads((REPO / "web" / "WEB-INF" / "validator" / f"{func}.jschema").read_text(encoding="utf-8"))
    assert schema["properties"]["language_selected"]["enum"] == list(NOTIFICATION_LANGUAGES)


@pytest.mark.parametrize(
    ("language", "ok"), [("en", True), ("hi", True), ("sat", True), ("en-IN", False), ("english", False), ("EN", False)]
)
def test_record_consent_schema_refuses_non_codes(language, ok):
    from dpdpcms_py.validators import validate_payload

    payload = {"_func": "record_consent", "user_id": "u", "policy_id": "p", "language_selected": language}
    errors = [e for e in validate_payload(payload) if "is not one of" in e]
    assert (errors == []) is ok


# ---- P13-05: web/vendor is under a supply-chain check ---------------------------------


def _vendor_audit():
    path = REPO / "scripts" / "supply_chain" / "vendor_audit.py"
    spec = importlib.util.spec_from_file_location("vendor_audit", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_vendored_files_match_the_manifest():
    audit = _vendor_audit()
    libraries = audit.load_manifest()
    assert audit.check_files(libraries) == []
    assert audit.check_review_dates(libraries, date.today()) == []


def test_unaccepted_advisory_fails_the_audit(monkeypatch):
    audit = _vendor_audit()
    libraries = audit.load_manifest()
    monkeypatch.setattr(
        audit,
        "_post",
        lambda url, body: {
            "results": [
                {"vulns": [{"id": "GHSA-new"}]} if q["package"]["name"] == "xlsx" else {} for q in body["queries"]
            ]
        },
    )
    monkeypatch.setattr(audit, "_get", lambda url: {"aliases": ["CVE-2099-0001"]})
    errors = audit.check_advisories(libraries)
    assert errors == ["xlsx 0.18.5: unreviewed advisory GHSA-new"]


def test_accepted_advisory_passes_until_its_review_date(monkeypatch):
    audit = _vendor_audit()
    libraries = audit.load_manifest()
    monkeypatch.setattr(
        audit,
        "_post",
        lambda url, body: {
            "results": [
                {"vulns": [{"id": "GHSA-4r6h-8v6p-xvw6"}]} if q["package"]["name"] == "xlsx" else {}
                for q in body["queries"]
            ]
        },
    )
    monkeypatch.setattr(audit, "_get", lambda url: {"aliases": ["CVE-2023-30533"]})
    assert audit.check_advisories(libraries) == []
    expired = audit.check_review_dates(libraries, date(2099, 1, 1))
    assert expired and all("expired" in e for e in expired)


def test_no_page_parses_spreadsheets_with_the_vendored_sheetjs():
    """The accepted SheetJS advisories need XLSX to PARSE input; keep it write-only."""
    pattern = re.compile(r"XLSX\s*\.\s*(read|readFile)\b")
    offenders = [
        str(path.relative_to(REPO))
        for path in (REPO / "web").rglob("*")
        if path.suffix in {".js", ".html"}
        and "vendor" not in path.parts
        and pattern.search(path.read_text(encoding="utf-8", errors="ignore"))
    ]
    assert offenders == []


def test_ci_runs_the_vendor_audit():
    workflow = (REPO / ".github" / "workflows" / "main.yml").read_text(encoding="utf-8")
    assert "python scripts/supply_chain/vendor_audit.py" in workflow


# ---- R14: production cannot run with an unrestricted outbound allowlist ---------------


def test_wildcard_allowlist_is_refused_in_production(monkeypatch):
    from dpdpcms_py import config

    monkeypatch.setenv("OUTBOUND_ALLOWED_HOSTS", "*")
    with pytest.raises(RuntimeError, match="production"):
        config._outbound_allowed_hosts("production")
    monkeypatch.setenv("OUTBOUND_ALLOWED_HOSTS", "hooks.example.in,*")
    with pytest.raises(RuntimeError, match="production"):
        config._outbound_allowed_hosts("production")
    monkeypatch.setenv("OUTBOUND_ALLOWED_HOSTS", "hooks.example.in")
    assert config._outbound_allowed_hosts("production") == ("hooks.example.in",)
    monkeypatch.setenv("OUTBOUND_ALLOWED_HOSTS", "*")
    assert config._outbound_allowed_hosts("staging") == ("*",)


# ---- P14-01: TSI_DPDP_CMS_ENV is a fixed, case-folded set ------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, "local"),
        ("", "local"),
        ("local", "local"),
        ("Production", "production"),
        (" PRODUCTION ", "production"),
        ("Staging", "staging"),
        ("test", "test"),
    ],
)
def test_environment_is_case_folded(monkeypatch, raw, expected):
    from dpdpcms_py import config

    if raw is None:
        monkeypatch.delenv("TSI_DPDP_CMS_ENV", raising=False)
    else:
        monkeypatch.setenv("TSI_DPDP_CMS_ENV", raw)
    assert config._environment() == expected


@pytest.mark.parametrize("raw", ["prod", "live", "dev", "production-in", "loc al"])
def test_unknown_environment_refuses_to_start(monkeypatch, raw):
    from dpdpcms_py import config

    monkeypatch.setenv("TSI_DPDP_CMS_ENV", raw)
    with pytest.raises(RuntimeError, match="TSI_DPDP_CMS_ENV must be one of"):
        config._environment()


def test_capitalised_production_still_refuses_wildcard(monkeypatch):
    from dpdpcms_py import config

    monkeypatch.setenv("TSI_DPDP_CMS_ENV", "Production")
    monkeypatch.setenv("OUTBOUND_ALLOWED_HOSTS", "*")
    with pytest.raises(RuntimeError, match="production"):
        config.Settings.load()
