"""Regression tests for the six bugs found re-verifying the "Exists" rows of
MeitY_BRD_API_Traceability_v5 (BRD Traceability sheet): PL-02 closed-purpose
deadlock, SA-12 retention floor, LG-04 recomputable audit chain, CC-09/CU-08
webhook sweep abort, NT-05 notification id field, CW-03/UD-05 one active
consent per fiduciary.

No database: the db helpers are monkeypatched.
"""

import inspect
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from dpdpcms_py import audit, webhooks
from dpdpcms_py.context import RequestContext
from dpdpcms_py.errors import ApiError
from dpdpcms_py.services import consent, governance, retention, roles

FID = "11111111-1111-1111-1111-111111111111"
REPO = Path(__file__).resolve().parents[2]

POLICY = {
    "en": {
        "data_processing_purposes": [
            {"id": "care", "name": "Care", "is_mandatory_for_service": True},
            {"id": "research", "name": "Research", "is_mandatory_for_service": False},
        ]
    }
}


def _ctx(service="consent", func="record_consent", payload=None, category="client", **kwargs):
    return RequestContext(
        path=f"/api/v1/{category}/{service}",
        category=category,
        service=service,
        payload={"_func": func, **(payload or {})},
        headers={},
        **kwargs,
    )


# ── PL-02 a closed purpose no longer deadlocks consent ─────────────────────
@pytest.fixture
def research_closed(monkeypatch):
    monkeypatch.setattr(consent.db, "one", lambda *a, **k: {"policy_content": POLICY})
    monkeypatch.setattr(consent.db, "all", lambda *a, **k: [{"purpose_id": "research"}])


def test_closed_purpose_can_be_declined(research_closed):
    closed = consent.check_consent_alignment(
        FID,
        "pol",
        "1",
        [{"data_point_id": "care", "consent_granted": True}, {"data_point_id": "research", "consent_granted": False}],
    )
    assert closed == {"research"}


def test_closed_purpose_cannot_be_granted(research_closed):
    with pytest.raises(ApiError) as exc:
        consent.check_consent_alignment(FID, "pol", "1", [{"data_point_id": "research", "consent_granted": True}])
    assert exc.value.status == 403


def test_closed_purpose_needs_no_decision():
    choices = [{"data_point_id": "care", "consent_granted": True}]
    consent.check_explicit_choices(POLICY, choices, {"research"})
    with pytest.raises(ApiError):
        consent.check_explicit_choices(POLICY, choices)  # an open purpose still needs one


# ── SA-12 a seven-year policy meets the seven-year floor ───────────────────
@pytest.mark.parametrize(
    "value, unit, ok",
    [
        (7, "YEARS", True),
        (84, "MONTHS", True),
        (2555, "DAYS", True),
        (99, "YEARS", True),
        (6, "YEARS", False),
        (83, "MONTHS", False),
        (2554, "DAYS", False),
    ],
)
def test_statutory_floor(value, unit, ok):
    assert retention.meets_statutory_floor(value, unit) is ok


class _ReachedDb(Exception):
    pass


def test_seven_year_policy_passes_the_floor_check(monkeypatch):
    def reached(*a, **k):
        raise _ReachedDb

    for name in ("one", "all", "execute", "insert_returning", "connection"):
        monkeypatch.setattr(retention.db, name, reached)
    svc = retention.RetentionService()
    with pytest.raises(_ReachedDb):  # got past validation, including the floor
        svc._apply(
            {"name": "Clinical", "retention_duration_value": 7, "retention_duration_unit": "YEARS"},
            FID,
        )


# ── LG-04 the audit chain is recomputable from stored rows ─────────────────
class _AuditCursor:
    def __init__(self, previous):
        self.previous = previous
        self.inserted = None

    def execute(self, sql, params=()):
        if sql.lstrip().startswith("INSERT INTO audit_logs"):
            self.inserted = params

    def fetchone(self):
        return self.previous

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _write(monkeypatch, previous, **kwargs):
    cursor = _AuditCursor(previous)

    class _Conn:
        def cursor(self):
            return cursor

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    @contextmanager
    def fake_connection():
        yield _Conn()

    monkeypatch.setattr(audit.db, "connection", fake_connection)
    audit.log_event(
        kwargs.get("user", "asha"),
        kwargs.get("fid", FID),
        "APP",
        None,
        kwargs.get("action", "CONSENT_GIVEN"),
        {"k": "v|with|pipes"},
        purpose_id="care",
        consent_status="GRANTED",
        initiator="PRINCIPAL",
        source_ip="10.0.0.1",
    )
    p = cursor.inserted
    # Column order of the INSERT in audit.log_event.
    row = dict(
        zip(
            (
                "id",
                "fiduciary_id",
                "timestamp",
                "user_id",
                "service_type",
                "service_id",
                "audit_action",
                "context_details",
                "prev_log_hash",
                "current_log_hash",
                "system_metadata",
                "purpose_id",
                "consent_status",
                "initiator",
                "source_ip",
            ),
            p,
            strict=True,
        )
    )
    row["system_metadata"] = {"python_port": True, "hash_v": audit.HASH_VERSION}
    return row


def test_stored_row_hash_recomputes(monkeypatch):
    row = _write(monkeypatch, None)
    assert row["user_id"] != "asha"  # stored pseudonymised...
    assert audit.row_hash(row["prev_log_hash"], row) == row["current_log_hash"]  # ...and hashed as stored
    assert row["timestamp"].tzinfo is None


def test_hash_covers_every_stored_column(monkeypatch):
    row = _write(monkeypatch, None)
    for column in ("fiduciary_id", "purpose_id", "consent_status", "initiator", "source_ip", "context_details"):
        tampered = {**row, column: "tampered"}
        assert audit.row_hash(row["prev_log_hash"], tampered) != row["current_log_hash"], column


def test_uuid_case_does_not_change_the_hash(monkeypatch):
    row = _write(monkeypatch, None, fid=FID.upper().replace("1", "A"))
    as_read_back = {**row, "fiduciary_id": str(row["fiduciary_id"]).lower()}
    assert audit.row_hash(row["prev_log_hash"], as_read_back) == row["current_log_hash"]


def test_timestamps_strictly_increase(monkeypatch):
    future = datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=1)
    row = _write(monkeypatch, {"current_log_hash": "abc", "timestamp": future})
    assert row["timestamp"] > future
    assert row["prev_log_hash"] == "abc"


def _chain(monkeypatch, n=3):
    rows, previous = [], None
    for i in range(n):
        prev = {"current_log_hash": rows[-1]["current_log_hash"], "timestamp": rows[-1]["timestamp"]} if rows else None
        rows.append(_write(monkeypatch, prev, action=f"A{i}"))
        previous = rows[-1]
    assert previous
    return rows


def test_verify_chain_intact_and_detects_tampering(monkeypatch):
    rows = _chain(monkeypatch)
    # SEC-10: the walk is NEWEST-first, so the query returns rows in DESC order.
    monkeypatch.setattr(audit.db, "all", lambda *a, **k: list(reversed(rows)))
    assert audit.verify_chain()["intact"] is True

    edited = [dict(r) for r in rows]
    edited[1]["context_details"] = '{"k": "edited"}'
    monkeypatch.setattr(audit.db, "all", lambda *a, **k: list(reversed(edited)))
    result = audit.verify_chain()
    assert not result["intact"]
    assert result["broken"] == [{"id": str(rows[1]["id"]), "reason": "CONTENT_MISMATCH"}]

    deleted = [rows[0], rows[2]]
    monkeypatch.setattr(audit.db, "all", lambda *a, **k: list(reversed(deleted)))
    assert audit.verify_chain()["broken"][0]["reason"] == "LINK_MISMATCH"


def test_legacy_rows_checked_for_linkage_only(monkeypatch):
    rows = _chain(monkeypatch, 2)
    rows[0] = {**rows[0], "system_metadata": {"python_port": True}, "context_details": "anything"}
    monkeypatch.setattr(audit.db, "all", lambda *a, **k: list(reversed(rows)))
    result = audit.verify_chain()
    assert result["intact"] and result["legacy_rows_linkage_only"] == 1


def test_chain_verification_scopes_to_the_callers_tenant(monkeypatch):
    """SEC-10: a tenant-scoped DPO/AUDITOR may verify its own ledger rows; the
    fiduciary_id is passed as the scope so neither it nor a global operator
    reads other tenants' row ids."""
    assert roles.required_permission("audit", "verify_audit_chain") == "audit:read"
    seen = {}
    from dpdpcms_py.services import governance as gov_mod

    def fake_verify(limit, fiduciary_id=None):
        seen["limit"] = limit
        seen["fiduciary_id"] = fiduciary_id
        return {"intact": True, "rows_checked": 5, "legacy_rows_linkage_only": 0, "truncated": False}

    monkeypatch.setattr(gov_mod, "verify_chain", fake_verify)
    ctx = _ctx("audit", "verify_audit_chain", category="admin", fiduciary_id=FID)
    ctx.auth_token = {"role": "ADMIN", "mfa": True, "email": "a@b"}
    ctx.permissions = {"*"}
    out = gov_mod.AuditService().verify_audit_chain(ctx)
    assert out["intact"] is True
    assert seen["fiduciary_id"] == FID


def test_audit_logs_append_only_migration():
    sql = (REPO / "db" / "19_audit_ledger_integrity.sql").read_text(encoding="utf-8")
    assert "BEFORE UPDATE OR DELETE ON audit_logs" in sql
    assert "BEFORE TRUNCATE ON audit_logs" in sql


# ── CC-09 / CU-08 an unsafe webhook host never aborts the sweep ────────────
@pytest.mark.parametrize("error", [ValueError("URL resolves to a private address"), OSError("DNS failure")])
def test_webhook_send_refusal_is_a_failed_attempt(monkeypatch, error):
    def boom(*a, **k):
        raise error

    monkeypatch.setattr(webhooks, "post_json", boom)
    status, message = webhooks._send(
        {"id": "d1", "event_type": "CONSENT_RECORDED", "payload": {}},
        {"webhook_url": "http://10.0.0.1/hook", "secret": None},
    )
    assert status is None
    assert message.startswith("refused:")


# ── NT-05 mark_notification_read accepts the schema's `id` ─────────────────
@pytest.mark.parametrize("field", ["id", "notification_id"])
def test_mark_notification_read_accepts_id(monkeypatch, field):
    seen = []
    monkeypatch.setattr(governance.db, "execute", lambda sql, params: seen.append(params) or 0)
    ctx = _ctx("notification", "mark_notification_read", {field: "n-1"}, fiduciary_id=FID)
    governance.NotificationService().mark_notification_read(ctx)
    assert seen[0][0] == "n-1"


def test_mark_notification_read_schema_accepts_either_field():
    from dpdpcms_py import validators

    assert validators.validate_payload({"_func": "mark_notification_read", "id": "n-1"}) == []
    assert validators.validate_payload({"_func": "mark_notification_read", "notification_id": "n-1"}) == []
    assert validators.validate_payload({"_func": "mark_notification_read"}) != []


# ── CW-03 / UD-05 one active consent per policy, not per fiduciary ─────────
def test_record_consent_retires_only_the_same_policy():
    source = inspect.getsource(consent.ConsentService.record_consent)
    assert "AND policy_id = %s AND is_active_consent IS TRUE" in source


A_RECORD = {
    "id": "rec-a",
    "user_id": "asha",
    "fiduciary_id": FID,
    "policy_id": "pol-a",
    "policy_version": "1",
    "jurisdiction": "IN",
    "language_selected": "en",
    "timestamp": datetime(2026, 1, 1),
    "consent_status_general": "GRANTED",
    "data_point_consents": [{"data_point_id": "care", "consent_granted": True}],
}
B_RECORD = {
    **A_RECORD,
    "id": "rec-b",
    "policy_id": "pol-b",
    "timestamp": datetime(2026, 2, 1),
    "data_point_consents": [{"data_point_id": "newsletter", "consent_granted": True}],
}


def test_validate_consent_sees_older_policy_record(monkeypatch):
    monkeypatch.setattr(consent.db, "all", lambda *a, **k: [B_RECORD, A_RECORD])
    monkeypatch.setattr(consent.db, "one", lambda *a, **k: None)
    monkeypatch.setattr(consent.db, "execute", lambda *a, **k: 1)
    ctx = _ctx(func="validate_consent", payload={"user_id": "asha", "required_purpose_id": "care"}, fiduciary_id=FID)
    result = consent.ConsentService().validate_consent(ctx)
    assert result["valid"] is True
    assert result["metadata"]["consent_record_id"] == "rec-a"


class _WithdrawCursor:
    def __init__(self, rows):
        self.rows, self.sql = rows, []

    def execute(self, sql, params=()):
        self.sql.append((sql, params))

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return {"id": f"new-{len(self.sql)}"}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _withdraw(monkeypatch, rows, payload):
    cursor = _WithdrawCursor(rows)

    class _Conn:
        def cursor(self):
            return cursor

    @contextmanager
    def fake_connection():
        yield _Conn()

    monkeypatch.setattr(consent.db, "connection", fake_connection)
    for name in ("_notify_principal", "log_event", "_raise_consent_alert"):
        monkeypatch.setattr(consent, name, lambda *a, **k: None)
    monkeypatch.setattr(webhooks, "queue_webhook", lambda *a, **k: None)
    ctx = _ctx(func="withdraw_consent", payload={"user_id": "asha", **payload}, fiduciary_id=FID)
    result = consent.ConsentService().withdraw_consent(ctx)
    retired = [p[0] for s, p in cursor.sql if s.startswith("UPDATE consent_records SET is_active_consent = FALSE")]
    return result, retired


def test_withdrawing_a_purpose_touches_only_the_policy_holding_it(monkeypatch):
    result, retired = _withdraw(monkeypatch, [B_RECORD, A_RECORD], {"purpose_ids": ["care"]})
    assert retired == ["rec-a"]
    assert len(result["consent_record_ids"]) == 1


def test_full_withdrawal_covers_every_policy(monkeypatch):
    result, retired = _withdraw(monkeypatch, [B_RECORD, A_RECORD], {})
    assert retired == ["rec-b", "rec-a"]
    assert len(result["consent_record_ids"]) == 2


def test_withdrawing_an_ungranted_purpose_is_still_rejected(monkeypatch):
    with pytest.raises(ApiError) as exc:
        _withdraw(monkeypatch, [B_RECORD, A_RECORD], {"purpose_ids": ["research"]})
    assert exc.value.status == 400
