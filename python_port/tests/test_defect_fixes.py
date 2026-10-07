"""Regression tests for the "Open Defects" sheet of MeitY_BRD_API_Traceability_v3.xlsx.

One section per defect number. No database: the db helpers are monkeypatched
with small fakes that record the SQL they receive.
"""

import http.server
import threading
from contextlib import contextmanager

import pytest
from dpdpcms_py import delivery, main, netutil, principal_otp, totp, worker
from dpdpcms_py.context import RequestContext
from dpdpcms_py.errors import ApiError
from dpdpcms_py.security import principal_token, token
from dpdpcms_py.services import admin, compliance, consent, roles
from dpdpcms_py.services.base import tenant_filter

FID = "11111111-1111-1111-1111-111111111111"
OTHER_FID = "22222222-2222-2222-2222-222222222222"


def _ctx(category="admin", service="operator", func="list_users", payload=None, headers=None, **kwargs):
    body = {"_func": func, **(payload or {})}
    return RequestContext(
        path=f"/api/v1/{category}/{service}",
        category=category,
        service=service,
        payload=body,
        headers=headers or {},
        **kwargs,
    )


def _bearer(raw: str) -> dict:
    return {"authorization": f"Bearer {raw}"}


# ── #1 principal_login verifies a stored, expiring, single-use OTP ───────────
class FakeOtpStore:
    """Just enough of principal_otps for request_principal_otp / principal_login."""

    def __init__(self, mode="EMAIL_OTP"):
        self.mode = mode
        self.rows = []
        self.webhooks = []

    def one(self, sql, params=()):
        if "rights_app_config" in sql:
            return {"otp_mode": self.mode, "otp_message_template": None}
        if "COUNT(*)" in sql:
            return {"count": len(self.rows)}
        if "FROM principal_otps" in sql:
            live = [r for r in self.rows if r["subject_hash"] == params[0] and r["consumed_at"] is None]
            return live[-1] if live else None
        raise AssertionError(sql)

    def execute(self, sql, params=()):
        if "SET consumed_at = NOW() WHERE id" in sql:
            row = next(r for r in self.rows if r["id"] == params[0])
            if row["consumed_at"] is not None:
                return 0
            row["consumed_at"] = "now"
            return 1
        if "attempts = attempts + 1" in sql:
            row = next(r for r in self.rows if r["id"] == params[1])
            row["attempts"] += 1
            if row["attempts"] >= params[0]:
                row["consumed_at"] = "now"
            return 1
        raise AssertionError(sql)

    @contextmanager
    def connection(self):
        store = self

        class Cursor:
            def execute(self, sql, params=()):
                if sql.lstrip().startswith("UPDATE"):
                    for r in store.rows:
                        if r["subject_hash"] == params[0]:
                            r["consumed_at"] = r["consumed_at"] or "superseded"
                else:
                    store.rows.append(
                        {
                            "id": len(store.rows) + 1,
                            "subject_hash": params[1],
                            "code_hash": params[2],
                            "attempts": 0,
                            "consumed_at": None,
                        }
                    )

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        class Conn:
            def cursor(self):
                return Cursor()

        yield Conn()


@pytest.fixture
def otp_store(monkeypatch):
    store = FakeOtpStore()
    monkeypatch.setattr(consent.db, "one", store.one)
    monkeypatch.setattr(consent.db, "execute", store.execute)
    monkeypatch.setattr(consent.db, "connection", store.connection)
    monkeypatch.setattr(consent, "log_event", lambda *a, **k: None)
    monkeypatch.setattr("dpdpcms_py.webhooks.queue_webhook", lambda *a, **k: store.webhooks.append((a, k)))
    return store


def _request_otp(user="asha@example.com"):
    ctx = _ctx("public", "principal", "request_principal_otp", {"fiduciary_id": FID, "user_id": user})
    return consent.PrincipalService().request_principal_otp(ctx)


def _login(otp, user="asha@example.com"):
    ctx = _ctx("public", "principal", "principal_login", {"fiduciary_id": FID, "user_id": user, "otp": otp})
    return consent.PrincipalService().principal_login(ctx)


def test_request_otp_never_returns_the_code(otp_store):
    out = _request_otp()
    assert "otp" not in out
    assert len(otp_store.rows) == 1
    # The code went out of band (OTP webhook), and only its HMAC was stored.
    (args, kwargs) = otp_store.webhooks[0]
    sent = args[2]["otp"]
    assert kwargs["category"] == "OTP"
    assert otp_store.rows[0]["code_hash"] != sent


def test_login_requires_an_otp(otp_store):
    ctx = _ctx("public", "principal", "principal_login", {"fiduciary_id": FID, "user_id": "u"})
    with pytest.raises(ApiError) as exc:
        consent.PrincipalService().principal_login(ctx)
    assert exc.value.status == 400


def test_login_rejects_wrong_code_and_accepts_right_code_once(otp_store):
    _request_otp()
    sent = otp_store.webhooks[0][0][2]["otp"]
    wrong = "000000" if sent != "000000" else "111111"
    with pytest.raises(ApiError) as exc:
        _login(wrong)
    assert exc.value.status == 401
    assert _login(sent)["token"]
    with pytest.raises(ApiError):  # single use
        _login(sent)


def test_code_is_bound_to_its_principal(otp_store):
    _request_otp("asha@example.com")
    sent = otp_store.webhooks[0][0][2]["otp"]
    with pytest.raises(ApiError):
        _login(sent, user="someone-else@example.com")


def test_code_dies_after_max_attempts(otp_store):
    _request_otp()
    sent = otp_store.webhooks[0][0][2]["otp"]
    wrong = "000000" if sent != "000000" else "111111"
    for _ in range(principal_otp.MAX_ATTEMPTS):
        with pytest.raises(ApiError):
            _login(wrong)
    with pytest.raises(ApiError):
        _login(sent)


def test_dummy_mode_refused_when_not_allowed(otp_store, monkeypatch):
    otp_store.mode = "DUMMY_OTP"
    monkeypatch.setattr(principal_otp, "dummy_allowed", lambda: False)
    with pytest.raises(ApiError) as exc:
        _login(principal_otp.DUMMY_CODE)
    assert exc.value.status == 401


def test_dummy_mode_still_checks_the_code(otp_store, monkeypatch):
    otp_store.mode = "DUMMY_OTP"
    monkeypatch.setattr(principal_otp, "dummy_allowed", lambda: True)
    with pytest.raises(ApiError):
        _login("9999")
    assert _login(principal_otp.DUMMY_CODE)["token"]


# ── #2 a principal JWT is never accepted as an admin token ────────────────
def test_principal_token_rejected_on_admin_route(monkeypatch):
    monkeypatch.setattr(main.db, "one", lambda *a, **k: pytest.fail("must reject before any lookup"))
    ctx = _ctx(headers=_bearer(principal_token(FID, "asha@example.com")))
    with pytest.raises(ApiError) as exc:
        main.authenticate(ctx)
    assert exc.value.status == 401


def test_token_without_active_operator_rejected(monkeypatch):
    monkeypatch.setattr(main.db, "one", lambda *a, **k: None)
    ctx = _ctx(headers=_bearer(token("gone@example.com", "Gone", "ADMIN")))
    with pytest.raises(ApiError) as exc:
        main.authenticate(ctx)
    assert exc.value.status == 401


def test_operator_bound_to_its_tenant_and_db_role(monkeypatch):
    operator = {"id": "op-1", "role": "DPO", "fiduciary_id": FID, "mfa_enabled": False}

    # main and roles share one db module, so a single fake answers both lookups.
    def fake_one(sql, params=()):
        return {"permissions": ["operator:read"]} if "FROM roles" in sql else operator

    monkeypatch.setattr(main.db, "one", fake_one)
    # The token claims ADMIN and the body names another tenant; neither is trusted.
    ctx = _ctx(payload={"fiduciary_id": OTHER_FID}, headers=_bearer(token("dpo@example.com", "Dpo", "ADMIN")))
    main.authenticate(ctx)
    assert ctx.actor_role == "DPO"
    assert ctx.fiduciary_id == FID
    assert ctx.payload["fiduciary_id"] == FID
    assert ctx.operator_id == "op-1"


# ── #3 enrol_mfa cannot overwrite an enabled secret from a password-only session
def test_enrol_mfa_refused_from_unverified_session(monkeypatch):
    monkeypatch.setattr(admin.db, "one", lambda *a, **k: {"mfa_enabled": True})
    monkeypatch.setattr(admin.db, "execute", lambda *a, **k: pytest.fail("secret must not be rewritten"))
    ctx = _ctx(func="enrol_mfa", auth_token={"email": "a@example.com", "mfa": False}, operator_id="op-1")
    with pytest.raises(ApiError) as exc:
        admin.OperatorService().enrol_mfa(ctx)
    assert exc.value.status == 403


def test_enrol_mfa_refused_when_already_enabled_and_verified(monkeypatch):
    monkeypatch.setattr(admin.db, "one", lambda *a, **k: {"mfa_enabled": True})
    monkeypatch.setattr(admin.db, "execute", lambda *a, **k: pytest.fail("secret must not be rewritten"))
    ctx = _ctx(func="enrol_mfa", auth_token={"email": "a@example.com", "mfa": True}, operator_id="op-1")
    with pytest.raises(ApiError) as exc:
        admin.OperatorService().enrol_mfa(ctx)
    assert exc.value.status == 409


# ── #4 operator email lookup decrypts the email column, never raises ────────
def test_recipient_email_decrypts_email_column(monkeypatch):
    seen = []

    def fake_one(sql, params=()):
        seen.append((sql, params))
        return {"email": "dpo@example.com"}

    monkeypatch.setattr(delivery.db, "one", fake_one)
    assert delivery._recipient_email("DPO", "op-1") == "dpo@example.com"
    sql, params = seen[0]
    assert "decode(email_enc, 'base64')" in sql
    assert sql.count("%s") == len(params)


def test_recipient_email_swallows_lookup_errors(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("invalid input syntax for type uuid")

    monkeypatch.setattr(delivery.db, "one", boom)
    assert delivery._recipient_email("OPERATOR", "not-a-uuid") is None


# ── #5 one failing sweep does not halt the others ──────────────────────────
def test_run_cycle_isolates_failing_sweep(monkeypatch):
    def boom():
        raise RuntimeError("smtp exploded")

    monkeypatch.setattr(worker.delivery, "process_pending_notifications", boom)
    monkeypatch.setattr(worker.webhooks, "process_pending_webhooks", lambda: {"dispatched": 1})
    for name in (
        "close_due_time_bound_purposes",
        "escalate_stale_alerts",
        "escalate_overdue_grievances",
        "run_retention_sweep",
        "execute_queued_jobs",
        "flag_overdue_purges",
        "release_expired_legal_holds",
        "prune_revoked_tokens",
    ):
        monkeypatch.setattr(worker.jobs, name, lambda name=name: {"ran": name})
    summary = worker.run_cycle()
    assert "smtp exploded" in summary["delivery"]["error"]
    assert summary["webhooks"] == {"dispatched": 1}
    assert summary["jobs"] == {"ran": "execute_queued_jobs"}


# ── #6 roles gate every admin write path, and are tenant-scoped ─────────────
def test_required_permission_mapping():
    assert roles.required_permission("consent", "record_consent") == "consent:write"
    assert roles.required_permission("purpose", "close_purpose") == "purpose:write"
    assert roles.required_permission("retention", "delete_retention_policy") == "retention:write"
    assert roles.required_permission("policy", "list_policies") == "policy:read"
    assert roles.required_permission("role", "create_role") == "role:manage"
    assert roles.required_permission("operator", "verify_mfa") is None
    # Unmapped services need a permission no seeded role holds.
    assert roles.required_permission("setup", "initial_setup") == "setup:write"


@pytest.mark.parametrize(
    "service,func",
    [("consent", "record_consent"), ("purpose", "close_purpose"), ("retention", "delete_retention_policy")],
)
def test_auditor_cannot_write(monkeypatch, service, func):
    monkeypatch.setattr(roles.db, "one", lambda *a, **k: {"permissions": ["consent:read", "policy:read", "audit:read"]})
    ctx = _ctx(service=service, func=func, auth_token={"role": "AUDITOR"})
    with pytest.raises(ApiError) as exc:
        roles.enforce_role_permission(ctx)
    assert exc.value.status == 403


def test_write_implies_read_and_wildcards():
    assert roles.has_permission({"consent:write"}, "consent:read")
    assert not roles.has_permission({"consent:read"}, "consent:write")
    assert roles.has_permission({"purge:*"}, "purge:write")
    assert roles.has_permission({"role:manage"}, "role:read")
    assert roles.has_permission({"*"}, "anything:write")


def test_role_lookup_is_scoped_to_tenant(monkeypatch):
    seen = []
    monkeypatch.setattr(roles.db, "one", lambda sql, params=(): seen.append((sql, params)) or {"permissions": []})
    roles.role_permissions(_ctx(auth_token={"role": "DPO"}, fiduciary_id=FID))
    sql, params = seen[0]
    assert "fiduciary_id" in sql
    assert params == ("DPO", FID)


def test_tenant_cannot_grant_permissions_it_lacks(monkeypatch):
    monkeypatch.setattr(roles.db, "one", lambda *a, **k: {"permissions": ["role:manage", "consent:read"]})
    ctx = _ctx(service="role", func="create_role", auth_token={"role": "DPO"}, fiduciary_id=FID)
    with pytest.raises(ApiError) as exc:
        roles._validate_permissions(ctx, ["consent:read", "*"])
    assert exc.value.status == 403


# ── #7 webhook POSTs are pinned to the validated IP and never follow redirects
class _Handler(http.server.BaseHTTPRequestHandler):
    seen_hosts: list = []
    status = 200

    def do_POST(self):  # noqa: N802 - http.server API
        type(self).seen_hosts.append(self.headers.get("Host"))
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(type(self).status)
        if type(self).status == 302:
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args):
        pass


@pytest.fixture
def local_server(monkeypatch):
    _Handler.seen_hosts = []
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Pretend validation resolved the (unresolvable) hostname to this server.
    monkeypatch.setattr(netutil, "resolve_public", lambda host: "127.0.0.1")
    yield server.server_address[1]
    server.shutdown()


def test_post_json_connects_to_pinned_ip(local_server):
    _Handler.status = 200
    status, body = netutil.post_json(f"http://hooks.invalid:{local_server}/x", {"a": 1})
    # hooks.invalid never resolves, so success proves no second DNS lookup.
    assert status == 200 and body == "ok"
    assert _Handler.seen_hosts == [f"hooks.invalid:{local_server}"]


def test_post_json_does_not_follow_redirects(local_server):
    _Handler.status = 302
    status, body = netutil.post_json(f"http://hooks.invalid:{local_server}/x", {"a": 1})
    assert status is None
    assert "redirect" in body
    assert len(_Handler.seen_hosts) == 1


# ── #8 TOTP codes are single-use and verify_mfa locks out ──────────────────
SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


def test_match_counter_returns_step():
    now = 1_700_000_000
    code = totp.totp_at(SECRET, now)
    assert totp.match_counter(SECRET, code, now) == now // 30
    assert totp.match_counter(SECRET, "000000" if code != "000000" else "111111", now) is None


class FakeOperatorRow:
    def __init__(self):
        self.last_counter = None
        self.failures = 0

    def one(self, sql, params=()):
        if "email_hmac" in sql:  # no operator matches an unknown token email
            return None
        if "mfa_secret_enc" in sql:
            return {
                "id": "op-1",
                "name": "Dpo",
                "email": "dpo@example.com",
                "status": "ACTIVE",
                "role": "DPO",
                "secret": SECRET,
                "locked": self.failures >= admin.MFA_MAX_FAILURES,
            }
        raise AssertionError(sql)

    def execute(self, sql, params=()):
        if "mfa_last_counter = %s" in sql:
            counter = params[0]
            if self.last_counter is not None and counter <= self.last_counter:
                return 0
            self.last_counter = counter
            self.failures = 0
            return 1
        if "mfa_failed_attempts = mfa_failed_attempts + 1" in sql:
            self.failures += 1
            return 1
        return 1


@pytest.fixture
def operator_row(monkeypatch):
    row = FakeOperatorRow()
    monkeypatch.setattr(admin.db, "one", row.one)
    monkeypatch.setattr(admin.db, "execute", row.execute)
    monkeypatch.setattr(admin, "log_event", lambda *a, **k: None)
    return row


def _verify(code):
    ctx = _ctx(func="verify_mfa", payload={"code": code}, auth_token={"email": "dpo@example.com"}, operator_id="op-1")
    return admin.OperatorService().verify_mfa(ctx)


def test_totp_code_cannot_be_replayed(operator_row):
    code = totp.totp_at(SECRET)
    assert _verify(code)["mfa"] is True
    with pytest.raises(ApiError) as exc:
        _verify(code)
    assert exc.value.status == 401


def test_verify_mfa_locks_after_repeated_failures(operator_row):
    code = totp.totp_at(SECRET)
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(admin.MFA_MAX_FAILURES):
        with pytest.raises(ApiError):
            _verify(wrong)
    with pytest.raises(ApiError) as exc:
        _verify(code)
    assert exc.value.status == 429


def test_verify_mfa_ignores_payload_user_id(operator_row):
    ctx = _ctx(func="verify_mfa", payload={"code": "123456", "user_id": "victim"}, auth_token={"email": "x"})
    with pytest.raises(ApiError) as exc:
        admin.OperatorService().verify_mfa(ctx)
    assert exc.value.status == 401


# ── #9 purge status enum and tenancy guards on by-id functions ─────────────
def test_update_purge_status_rejects_unknown_status(monkeypatch):
    monkeypatch.setattr(compliance.db, "execute", lambda *a, **k: pytest.fail("must validate first"))
    ctx = _ctx(service="compliance", func="update_purge_status", payload={"id": "p1", "status": "WHATEVER"})
    with pytest.raises(ApiError) as exc:
        compliance.ComplianceService().update_purge_status(ctx)
    assert exc.value.status == 400


def test_tenant_filter():
    assert tenant_filter(_ctx()) == ("", [])
    assert tenant_filter(_ctx(fiduciary_id=FID)) == (" AND fiduciary_id = %s", [FID])
    assert tenant_filter(_ctx(fiduciary_id=FID), "id") == (" AND id = %s", [FID])


def test_recovery_key_scoped_to_tenant_non_admins(monkeypatch):
    seen = []
    monkeypatch.setattr(admin.db, "execute", lambda sql, params=(): seen.append((sql, params)) or 0)
    ctx = _ctx(func="generate_recovery_key", payload={"user_id": "victim"}, fiduciary_id=FID)
    with pytest.raises(ApiError) as exc:
        admin.OperatorService().generate_recovery_key(ctx)
    assert exc.value.status == 404
    sql, params = seen[0]
    assert "fiduciary_id = %s" in sql and "role != 'ADMIN'" in sql
    assert params[-1] == FID


def test_get_breach_scoped_to_tenant(monkeypatch):
    seen = []
    monkeypatch.setattr(compliance.db, "one", lambda sql, params=(): seen.append((sql, params)))
    ctx = _ctx(service="breach", func="get_breach", payload={"id": "b1"}, fiduciary_id=FID)
    with pytest.raises(ApiError):
        compliance.BreachService().get_breach(ctx)
    assert seen[0][1] == ("b1", FID)
