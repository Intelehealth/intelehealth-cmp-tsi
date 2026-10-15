"""Workbook v9 (P11-xx) regressions, against a REAL Postgres.

Reuses the transaction-per-test fixture and seed helpers of
test_integration_db.py, and skips the same way when no database is reachable.
"""

import psycopg
import pytest
from tests.test_integration_db import (
    _DB_READY,
    REPO,
    _ctx,
    _seed_consent,
    _seed_policy_version,
    _seed_tenant,
    real_db,
)

pytestmark = pytest.mark.skipif(not _DB_READY, reason="no live Postgres configured")


def _seed_ropa(cur, fid, pol, purpose="care"):
    cur.execute(
        "INSERT INTO ropa_entries (fiduciary_id, activity_name, purpose, legal_basis, linked_policy_ids, source_purpose_id, status)"
        " VALUES (%s, %s, %s, 'consent', %s, %s, 'active')",
        (fid, purpose, purpose, real_db.as_jsonb([pol]), purpose),
    )


@pytest.mark.parametrize(
    "forged",
    [
        {"data_point_id": "research", "consent_granted": True},
        {"data_point_id": "research", "status": "true"},
        {"data_point_id": "research", "consent_granted": "True"},
        {"data_point_id": "research", "consent_granted": 1},
        {"data_point_id": "research", "status": "GRANTED"},
        {"purpose_id": "Research", "consent_granted": [1]},
    ],
)
def test_maintenance_guard_reads_granted_as_the_gate_does(tx, forged):
    """P11-01: every truthy spelling validate_consent honours is refused."""
    from dpdpcms_py.services.consent import _point_granted

    assert _point_granted(forged)
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("research",))
        _seed_consent(cur, fid, pol, "asha", purposes=("research",), granted=False)
        real_db.allow_consent_maintenance(cur)
        with pytest.raises(psycopg.errors.InsufficientPrivilege), tx.transaction():
            cur.execute(
                "UPDATE consent_records SET data_point_consents = %s WHERE fiduciary_id = %s",
                (real_db.as_jsonb([forged]), fid),
            )


def test_maintenance_guard_still_allows_real_maintenance(tx):
    """P11-01: the guard must not block an erasure re-key that keeps a refusal refused."""
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("research",))
        _seed_consent(cur, fid, pol, "asha", purposes=("research",), granted=False)
        real_db.allow_consent_maintenance(cur)
        cur.execute(
            "UPDATE consent_records SET user_id = 'erased:x', data_point_consents = %s WHERE fiduciary_id = %s",
            (real_db.as_jsonb([{"data_point_id": "research", "consent_granted": False, "status": "withdrawn"}]), fid),
        )
        assert cur.rowcount == 1


@pytest.mark.parametrize("value", ['{"care": true}', '"x"', "null", "5"])
def test_maintenance_guard_rejects_a_non_array_payload(tx, value):
    """P11-02: a non-array wiped every decision on an append-only table."""
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        real_db.allow_consent_maintenance(cur)
        with pytest.raises(psycopg.errors.InsufficientPrivilege), tx.transaction():
            cur.execute(
                "UPDATE consent_records SET data_point_consents = %s::jsonb WHERE fiduciary_id = %s", (value, fid)
            )


def test_activating_a_version_retires_the_one_it_supersedes(tx):
    """P11-03 / CU-05: two ACTIVE versions let consent rest on a superseded
    notice, for a purpose the current notice had dropped."""
    from dpdpcms_py.errors import ApiError
    from dpdpcms_py.services.catalog import PolicyService
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur, purposes=("care", "research"))
        _seed_consent(cur, fid, pol, "asha", purposes=("care", "research"))
        _seed_ropa(cur, fid, pol)
        _seed_policy_version(cur, fid, pol, "v2", "DRAFT", purposes=("care",))
    PolicyService().publish_policy(_ctx(fid, {"policy_id": pol, "version": "v2"}))
    with tx.cursor() as cur:
        cur.execute("SELECT version, status FROM consent_policies WHERE id = %s", (pol,))
        assert {r["version"]: r["status"] for r in cur.fetchall()} == {"v1": "ARCHIVED", "v2": "ACTIVE"}
    # A new principal cannot consent against the superseded notice ...
    with pytest.raises(ApiError) as exc:
        ConsentService().record_consent(
            _ctx(
                fid,
                {
                    "user_id": "ravi",
                    "policy_id": pol,
                    "version": "v1",
                    "data_point_consents": [
                        {"data_point_id": "care", "consent_granted": True},
                        {"data_point_id": "research", "consent_granted": True},
                    ],
                },
            )
        )
    assert exc.value.status == 409
    out = ConsentService().validate_consent(_ctx(fid, {"user_id": "ravi", "required_purpose_id": "research"}))
    assert out["valid"] is False
    # ... and an unversioned consent lands on the served one.
    ConsentService().record_consent(
        _ctx(
            fid,
            {
                "user_id": "ravi",
                "policy_id": pol,
                "data_point_consents": [{"data_point_id": "care", "consent_granted": True}],
            },
        )
    )
    with tx.cursor() as cur:
        cur.execute("SELECT policy_version FROM consent_records WHERE fiduciary_id = %s AND user_id = 'ravi'", (fid,))
        assert [r["policy_version"] for r in cur.fetchall()] == ["v2"]


def test_a_newer_version_closes_the_older_reconsent_demand(tx):
    """P11-03: one principal accumulated a PENDING demand per published version."""
    from dpdpcms_py.services.catalog import PolicyService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        _seed_ropa(cur, fid, pol)
        _seed_policy_version(cur, fid, pol, "v2", "DRAFT")
        _seed_policy_version(cur, fid, pol, "v3", "DRAFT")
    PolicyService().publish_policy(_ctx(fid, {"policy_id": pol, "version": "v2"}))
    PolicyService().publish_policy(_ctx(fid, {"policy_id": pol, "version": "v3"}))
    with tx.cursor() as cur:
        cur.execute("SELECT version FROM consent_policies WHERE id = %s AND status = 'ACTIVE'", (pol,))
        assert [r["version"] for r in cur.fetchall()] == ["v3"]
        cur.execute(
            "SELECT policy_version FROM reconsent_requests WHERE fiduciary_id = %s AND status = 'PENDING'", (fid,)
        )
        assert [r["policy_version"] for r in cur.fetchall()] == ["v3"]


def test_future_dated_version_supersedes_only_once_in_effect(tx):
    """P11-03: a future-dated ACTIVE version leaves the current one served."""
    from dpdpcms_py.services.catalog import retire_all_superseded_versions, served_policy_version

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_policy_version(cur, fid, pol, "v2", "ACTIVE")
        cur.execute(
            "UPDATE consent_policies SET effective_date = NOW() + INTERVAL '1 day' WHERE id = %s AND version = 'v2'",
            (pol,),
        )
    retire_all_superseded_versions()
    assert served_policy_version(pol, fid) == "v1"
    with tx.cursor() as cur:
        cur.execute(
            "UPDATE consent_policies SET effective_date = NOW() + INTERVAL '1 second' WHERE id = %s AND version = 'v2'",
            (pol,),
        )
        cur.execute(
            "UPDATE consent_policies SET effective_date = NOW() - INTERVAL '1 day' WHERE id = %s AND version = 'v1'",
            (pol,),
        )
        cur.execute(
            "UPDATE consent_policies SET effective_date = NOW() - INTERVAL '1 hour' WHERE id = %s AND version = 'v2'",
            (pol,),
        )
    retire_all_superseded_versions()
    assert served_policy_version(pol, fid) == "v2"
    with tx.cursor() as cur:
        cur.execute("SELECT status FROM consent_policies WHERE id = %s AND version = 'v1'", (pol,))
        assert cur.fetchone()["status"] == "ARCHIVED"


def test_whole_account_erasure_is_found_by_the_audit_purpose_filter(tx):
    """P11-04 / LG-05: 'ALL' was lower-cased away and found by no spelling."""
    from dpdpcms_py import audit

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
    audit.log_event("SYSTEM", fid, "SYSTEM", None, "PURGE_STATUS_UPDATED", {"k": "v"}, purpose_id="ALL")
    audit.log_event("SYSTEM", fid, "SYSTEM", None, "CONSENT_GIVEN", {"k": "v"}, purpose_id="care")
    rows = audit.list_logs({"fiduciary_id": fid, "purpose_id": "ALL"})
    assert [r["audit_action"] for r in rows] == ["PURGE_STATUS_UPDATED"]
    for spelling in ("care", " CARE ", "Care"):
        rows = audit.list_logs({"fiduciary_id": fid, "purpose_id": spelling})
        assert [r["audit_action"] for r in rows] == ["CONSENT_GIVEN"], spelling


def test_withdrawal_reaches_only_registered_processors(tx):
    """P11-05 / CW-08: every ACTIVE app was treated as a processor."""
    from dpdpcms_py.services.consent import ConsentService

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        ids = {}
        for name, dpa, category in (
            ("lab", "DPA-1", "NOTIFICATION"),  # a processor for this event class
            ("billing", None, "NOTIFICATION"),  # endpoint, but no processing agreement
            ("pharmacy", "DPA-2", "PURGE"),  # a processor, for another event class
            ("integrator", "DPA-3", None),  # an API key with no processor endpoint
        ):
            cur.execute(
                "INSERT INTO apps (fiduciary_id, name, status, dpa_reference) VALUES (%s, %s, 'ACTIVE', %s) RETURNING id",
                (fid, name, dpa),
            )
            ids[name] = str(cur.fetchone()["id"])
            if category:
                cur.execute(
                    "INSERT INTO processor_webhook_configs (app_id, fiduciary_id, category, webhook_url, secret_enc)"
                    " VALUES (%s, %s, %s, 'https://p.example.org/hook', '')",
                    (ids[name], fid, category),
                )
    out = ConsentService().withdraw_consent(_ctx(fid, {"user_id": "asha", "purpose_ids": ["care"]}))
    assert out["processors_notified"] == 1
    with tx.cursor() as cur:
        cur.execute("SELECT recipient_id FROM alerts WHERE fiduciary_id = %s AND recipient_type = 'PROCESSOR'", (fid,))
        assert [r["recipient_id"] for r in cur.fetchall()] == [ids["lab"]]
        cur.execute("SELECT app_id FROM webhook_deliveries WHERE fiduciary_id = %s AND app_id IS NOT NULL", (fid,))
        assert [str(r["app_id"]) for r in cur.fetchall()] == [ids["lab"]]


def test_erasure_scrubs_the_identifier_from_fiduciary_and_processor_alerts(tx):
    """P11-06: only PRINCIPAL alerts were scrubbed."""
    from dpdpcms_py.services.compliance import erase_cms_copy
    from dpdpcms_py.services.lifecycle import record_alert

    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        cur.execute("INSERT INTO apps (fiduciary_id, name, status) VALUES (%s, 'lab', 'ACTIVE') RETURNING id", (fid,))
        app_id = str(cur.fetchone()["id"])
    record_alert(fid, "CONSENT_WITHDRAWN", None, {"user_id": "asha"})
    record_alert(fid, "CONSENT_WITHDRAWN", None, {"user_id": "asha"}, recipient_type="PROCESSOR", recipient_id=app_id)
    record_alert(fid, "CONSENT_WITHDRAWN", None, {"user_id": "ravi"})
    with tx.cursor() as cur:
        counts = erase_cms_copy(fid, "asha", cur=cur, pending_files=set())
        cur.execute("SELECT payload ->> 'user_id' AS uid FROM alerts WHERE fiduciary_id = %s", (fid,))
        uids = [r["uid"] for r in cur.fetchall()]
    assert counts["alerts"] == 2
    assert "asha" not in uids and "ravi" in uids


def test_active_consent_without_a_policy_returns_every_active_record(tx):
    """P11-07: one of several active records was returned as the whole answer."""
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
    out = service.get_active_consent(_ctx(fid, {"user_id": "asha"}))
    assert out["active_record_count"] == 2
    assert sorted(r["policy_id"] for r in out["active_records"]) == sorted([pol_a, pol_b])
    one = service.get_active_consent(_ctx(fid, {"user_id": "asha", "policy_id": pol_b}))
    assert one["policy_id"] == pol_b and one["active_record_count"] == 1


def test_closure_finds_a_lifecycle_row_that_was_never_canonicalised(tx):
    """P11-08: a pre-26 ' Marketing' row was skipped by an exact-match lookup."""
    from dpdpcms_py.services.lifecycle import close_purpose_exec

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur, purposes=("marketing",))
        cur.execute("ALTER TABLE purpose_lifecycle DISABLE TRIGGER trg_purpose_lifecycle_canonical")
        cur.execute(
            "INSERT INTO purpose_lifecycle (fiduciary_id, purpose_id, state, duration_type, consent_expiry_days, opened_at)"
            " VALUES (%s, ' Marketing', 'OPEN', 'TIME_BOUND', 1, NOW() - INTERVAL '2 days')",
            (fid,),
        )
        cur.execute("ALTER TABLE purpose_lifecycle ENABLE TRIGGER trg_purpose_lifecycle_canonical")
    out = close_purpose_exec(fid, " Marketing", reason="test")
    assert out["state"] == "CLOSED"
    with tx.cursor() as cur:
        cur.execute("SELECT state FROM purpose_lifecycle WHERE fiduciary_id = %s", (fid,))
        assert cur.fetchone()["state"] == "CLOSED"


def test_a_failed_time_bound_closure_is_reported_as_an_error(tx, monkeypatch):
    """P11-08: a swallowed failure read as 'closed: 0'."""
    from dpdpcms_py import jobs

    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur, purposes=("marketing",))
        cur.execute(
            "INSERT INTO purpose_lifecycle (fiduciary_id, purpose_id, state, duration_type, consent_expiry_days, opened_at)"
            " VALUES (%s, 'marketing', 'OPEN', 'TIME_BOUND', 1, NOW() - INTERVAL '2 days')",
            (fid,),
        )

    def boom(**_kwargs):
        raise RuntimeError("closure failed")

    monkeypatch.setattr(jobs, "close_purpose_exec", boom)
    out = jobs.close_due_time_bound_purposes()
    assert out["errors"] >= 1 and "error" in out


def test_legacy_templates_are_archived_not_merged_into_live_types(tx):
    """P11-09: db/26 kept two template rows the API refuses and the console hides.
    P12-07: they are archived and removed; their text, written for another
    event, never fills a language of the live type."""
    with tx.cursor() as cur:
        fid, _ = _seed_tenant(cur)
        for ntype, text in (("EXPIRY_NOTIFICATION", "legacy expiry"), ("PURGE_ONHOLD_NOTIFICATION", "legacy hold")):
            cur.execute(
                "INSERT INTO notification_message_templates (fiduciary_id, notification_type, messages) VALUES (%s, %s, %s)",
                (fid, ntype, real_db.as_jsonb({"en": text, "hi": text + " hi"})),
            )
        cur.execute(
            "INSERT INTO notification_message_templates (fiduciary_id, notification_type, messages)"
            " VALUES (%s, 'PURPOSE_CLOSED', %s)",
            (fid, real_db.as_jsonb({"en": "live text"})),
        )
        cur.execute((REPO / "db" / "27_p11_remediation.sql").read_text(encoding="utf-8"))
        cur.execute(
            "SELECT notification_type, messages FROM notification_message_templates WHERE fiduciary_id = %s", (fid,)
        )
        live = {r["notification_type"]: r["messages"] for r in cur.fetchall()}
        cur.execute(
            "SELECT notification_type FROM notification_message_templates_archive WHERE fiduciary_id = %s", (fid,)
        )
        archived = {r["notification_type"] for r in cur.fetchall()}
    assert set(live) == {"PURPOSE_CLOSED"}
    assert live["PURPOSE_CLOSED"] == {"en": "live text"}
    assert archived == {"EXPIRY_NOTIFICATION", "PURGE_ONHOLD_NOTIFICATION"}
