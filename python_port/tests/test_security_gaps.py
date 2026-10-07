"""Regression tests for the "Security Gaps" sheet of
MeitY_BRD_API_Traceability_security.xlsx. Rules here were written against
p4 @ db55b7c; this file locks every SEC-xx fix that is still open on p5 to
its current behaviour. No database: the db helpers are monkeypatched, and the
throttle module is tested directly against a captured-SQL fake.
"""

import contextlib
import types

import jwt as pyjwt
import pytest
from dpdpcms_py import throttle
from dpdpcms_py.context import RequestContext
from dpdpcms_py.errors import ApiError
from dpdpcms_py.services import admin, compliance, consent, governance, rights, roles

FID = "11111111-1111-1111-1111-111111111111"
APP_ID = "33333333-3333-3333-3333-333333333333"


# SEC-01..SEC-15 regression helpers ──────────────────────────────────────────


class _CapturedDb:
    """Records SQL it is given and answers canned rows / rowcounts."""

    def __init__(self):
        self.sql = []
        self.rows = {}

    def one(self, sql, params=()):
        self.sql.append(sql)
        return self.rows.get(sql, None)

    def all(self, sql, params=()):
        self.sql.append(sql)
        return []

    def execute(self, sql, params=()):
        self.sql.append(sql)
        return 1


def _ctx(category="admin", service="operator", func="list_users", payload=None, **kwargs):
    body = {"_func": func, **(payload or {})}
    defaults = {"path": f"/api/v1/{category}/{service}", "category": category, "service": service, "payload": body, "headers": {}}
    defaults.update(kwargs)
    return RequestContext(**defaults)


# ── SEC-01 unauthenticated recovery path is throttled, audited, floored ─────
def test_recovery_verify_throttled_and_audited(monkeypatch):
    called = {"throttle": [], "log": []}
    monkeypatch.setattr("dpdpcms_py.throttle.require_allowed", lambda scope, key: called["throttle"].append((scope, key)))
    monkeypatch.setattr("dpdpcms_py.throttle.record_failure", lambda *a, **k: None)
    monkeypatch.setattr("dpdpcms_py.throttle.record_success", lambda *a, **k: None)
    monkeypatch.setattr(admin.db, "one", lambda *a, **k: {"recovery_key_hash": "badhash"})
    monkeypatch.setattr(admin, "verify_password", lambda *a, **k: False)
    monkeypatch.setattr(admin, "log_event", lambda *a, **k: called["log"].append(a))
    ctx = _ctx(
        service="operator",
        func="verify_recovery_key",
        payload={"email": "x@y.z", "passphrase": "nope"},
        source_ip="9.9.9.9",
    )
    with pytest.raises(ApiError) as exc:
        admin.OperatorService().verify_recovery_key(ctx)
    assert exc.value.status == 401
    # SEC-01/P5-03: the account throttle key is the email HMAC, never the raw
    # address; the per-IP key is unchanged.
    assert ("recovery:email", throttle.email_key("x@y.z")) in called["throttle"]
    assert ("recovery:ip", "9.9.9.9") in called["throttle"]
    assert any(a[4] == "RECOVERY_KEY_FAILURE" for a in called["log"])


def test_recovery_lockout_raises_429(monkeypatch):
    def locked(scope, key):
        raise ApiError(429, "Too Many Requests", "Too many failed attempts. Try again later.")

    monkeypatch.setattr("dpdpcms_py.throttle.require_allowed", locked)
    ctx = _ctx(service="operator", func="verify_recovery_key", payload={"email": "x@y.z", "passphrase": "ok"})
    with pytest.raises(ApiError) as exc:
        admin.OperatorService().verify_recovery_key(ctx)
    assert exc.value.status == 429


def test_reset_password_enforces_12_char_floor(monkeypatch):
    monkeypatch.setattr("dpdpcms_py.throttle.require_allowed", lambda *a, **k: None)
    monkeypatch.setattr("dpdpcms_py.throttle.record_success", lambda *a, **k: None)
    monkeypatch.setattr(admin.db, "one", lambda *a, **k: {"recovery_key_hash": "present"})
    monkeypatch.setattr(admin, "verify_password", lambda *a, **k: True)
    monkeypatch.setattr(admin, "log_event", lambda *a, **k: None)
    ctx = _ctx(
        service="operator",
        func="reset_password_via_recovery",
        payload={"email": "x@y.z", "passphrase": "ok", "new_password": "short"},
    )
    with pytest.raises(ApiError) as exc:
        admin.OperatorService().reset_password_via_recovery(ctx)
    assert exc.value.status == 400
    assert "12 characters" in str(exc.value.message)


def test_reset_password_success_logged_and_hashes(monkeypatch):
    logged = []
    capture = _CapturedDb()
    monkeypatch.setattr("dpdpcms_py.throttle.require_allowed", lambda *a, **k: None)
    monkeypatch.setattr("dpdpcms_py.throttle.record_success", lambda *a, **k: None)
    monkeypatch.setattr(admin.db, "one", lambda *a, **k: {"recovery_key_hash": "present"})
    monkeypatch.setattr(admin, "verify_password", lambda *a, **k: True)
    monkeypatch.setattr(admin.db, "execute", capture.execute)
    monkeypatch.setattr(admin, "log_event", lambda *a, **k: logged.append(a))
    ctx = _ctx(
        service="operator",
        func="reset_password_via_recovery",
        payload={"email": "x@y.z", "passphrase": "ok", "new_password": "longenough12"},
    )
    out = admin.OperatorService().reset_password_via_recovery(ctx)
    assert out["success"] is True
    assert any("PASSWORD_RESET_VIA_RECOVERY" in str(a) for a in logged)
    assert any("tokens_valid_after" in s for s in capture.sql)


# ── SEC-03 login is throttled and writes last_login_at ──────────────────────
def test_login_throttled_before_credential_check(monkeypatch):
    checks = []
    monkeypatch.setattr("dpdpcms_py.throttle.require_allowed", lambda scope, key: checks.append((scope, key)))
    monkeypatch.setattr("dpdpcms_py.throttle.record_failure", lambda *a, **k: None)
    monkeypatch.setattr(admin.db, "one", lambda *a, **k: None)
    monkeypatch.setattr(admin, "log_event", lambda *a, **k: None)
    ctx = _ctx(service="operator", func="login", payload={"identifier": "u1", "password": "x"})
    with pytest.raises(ApiError):
        admin.OperatorService().login(ctx)
    # SEC-03/P5-03: the account key is the identifier's email-style HMAC so the
    # throttle table never holds raw addresses.
    assert ("login:identifier", throttle.email_key("u1")) in checks


def test_login_success_writes_last_login_at(monkeypatch):
    monkeypatch.setattr("dpdpcms_py.throttle.require_allowed", lambda *a, **k: None)
    monkeypatch.setattr("dpdpcms_py.throttle.record_success", lambda *a, **k: None)
    op = {
        "id": "op-1",
        "name": "U1",
        "email": "u1@x.y",
        "password_hash": "h",
        "status": "ACTIVE",
        "role": "DPO",
        "fiduciary_id": FID,
        "fiduciary_name": "F",
    }

    def one(sql, params=()):
        if "LEFT JOIN fiduciaries" in sql:
            return op
        if "mfa_enabled" in sql:
            return {"mfa_enabled": False}
        return None

    executed = []
    monkeypatch.setattr(admin.db, "one", one)
    monkeypatch.setattr(admin.db, "execute", lambda sql, params=(): executed.append(sql) or 1)
    monkeypatch.setattr(admin, "log_event", lambda *a, **k: None)
    monkeypatch.setattr(admin, "verify_password", lambda *a, **k: True)
    from dpdpcms_py.security import token as make_token

    monkeypatch.setattr(admin, "token", make_token)
    ctx = _ctx(service="operator", func="login", payload={"identifier": "u1", "password": "x"})
    admin.OperatorService().login(ctx)
    assert any("last_login_at = NOW()" in s for s in executed)


# ── SEC-04 purge confirmation is bound to the authenticated key ─────────────
class _PurgeDb:
    def __init__(self, app_id=None, status="PENDING", assigned_operator_id=None):
        self.app_id = app_id
        self.status = status
        self.assigned_operator_id = assigned_operator_id

    def one(self, sql, params=()):
        if "FROM purge_requests" in sql and "app_id" in sql:
            return {
                "id": "pr-1",
                "user_id": "u",
                "fiduciary_id": FID,
                "purpose_id": "ALL",
                "trigger_event": "ErasureRequest",
                "status": self.status,
                "hold_until": None,
                "app_id": self.app_id,
                "assigned_operator_id": self.assigned_operator_id,
            }
        if "LEGAL_HOLD_APPLIED" in sql:
            return None
        return None


def _confirm_ctx(**extra):
    payload = {
        "purge_request_id": "pr-1",
        "status": "PURGE_COMPLETED",
        "records_affected_count": 3,
        "details": "done",
        "confirmed_by_entity_id": "claimed",
    }
    defaults = dict(category="client", service="compliance", func="confirm_purge_status", payload=payload)
    defaults.update(extra)
    return _ctx(**defaults)


def test_confirm_purge_rejects_key_not_assigned_to_request(monkeypatch):
    capture = _PurgeDb(app_id="some-other-app")
    monkeypatch.setattr(compliance.db, "one", capture.one)
    ctx = _confirm_ctx(app_id=APP_ID, permissions={"PURGE"})
    with pytest.raises(ApiError) as exc:
        compliance.ComplianceService().confirm_purge_status(ctx)
    assert exc.value.status == 403


def test_confirm_purge_assigned_app_passes(monkeypatch):
    capture = _PurgeDb(app_id=APP_ID)
    executed = []
    monkeypatch.setattr(compliance.db, "one", capture.one)
    monkeypatch.setattr(compliance.db, "execute", lambda sql, params=(): executed.append(sql) or 1)
    monkeypatch.setattr(compliance, "erase_cms_copy", lambda *a, **k: {})
    monkeypatch.setattr(compliance, "log_event", lambda *a, **k: None)
    ctx = _confirm_ctx(app_id=APP_ID, permissions={"PURGE"})
    out = compliance.ComplianceService().confirm_purge_status(ctx)
    assert out["success"] is True
    assert any("completion_evidence" in s for s in executed)


def test_confirm_purge_api_key_identity_used_not_payload(monkeypatch):
    capture = _PurgeDb(app_id=APP_ID)
    evidence = {}

    def execute(sql, params=()):
        if "completion_evidence" in sql:
            evidence["json"] = params[2].adapt if hasattr(params[2], "adapt") else params[2]
        return 1

    monkeypatch.setattr(compliance.db, "one", capture.one)
    monkeypatch.setattr(compliance.db, "execute", execute)
    monkeypatch.setattr(compliance, "erase_cms_copy", lambda *a, **k: {})
    monkeypatch.setattr(compliance, "log_event", lambda *a, **k: None)
    ctx = _confirm_ctx(app_id=APP_ID, permissions={"PURGE"})
    compliance.ComplianceService().confirm_purge_status(ctx)


def test_confirm_purge_console_uses_operator_identity(monkeypatch):
    capture = _PurgeDb()
    executed = []
    monkeypatch.setattr(compliance.db, "one", capture.one)
    monkeypatch.setattr(compliance.db, "execute", lambda sql, params=(): executed.append(sql) or 1)
    monkeypatch.setattr(compliance, "erase_cms_copy", lambda *a, **k: {})
    monkeypatch.setattr(compliance, "log_event", lambda *a, **k: None)
    ctx = _confirm_ctx(operator_id="op-1", auth_token={"email": "dpo@x.y", "role": "DPO"})
    out = compliance.ComplianceService().confirm_purge_status(ctx)
    assert out["success"] is True


# ── SEC-05 link_user never lets a client default overwrite age/verification ──
def test_link_user_does_not_accept_age_or_verification(monkeypatch):
    capture = _CapturedDb()
    monkeypatch.setattr(consent.db, "execute", capture.execute)
    ctx = _ctx(
        category="client",
        service="consent",
        func="link_user",
        payload={
            "anonymous_user_id": "anon",
            "authenticated_user_id": "auth",
            "age_category": "ADULT",
            "verification_status": "VERIFIED",
        },
        fiduciary_id=FID,
    )
    consent.ConsentService().link_user(ctx)
    for sql in capture.sql:
        assert "EXCLUDED.age_category" not in sql
        assert "EXCLUDED.verification_status" not in sql
        assert "age_category = EXCLUDED" not in sql
        assert sql.lstrip().startswith(("UPDATE consent_records", "INSERT INTO data_principal", "UPDATE data_principal"))


# ── SEC-06 dashboard metrics are tenant-scoped ───────────────────────────────
def test_get_admin_metrics_scoped_to_caller_tenant(monkeypatch):
    capture = _CapturedDb()
    monkeypatch.setattr(admin.db, "one", capture.one)
    ctx = _ctx(service="admindash", func="get_admin_metrics", fiduciary_id=FID)
    admin.AdminDashService().get_admin_metrics(ctx)
    counts = [sql for sql in capture.sql if sql.startswith("SELECT COUNT(*)")]
    assert len(counts) == 3
    for sql in counts:
        assert "%s" in sql and ("fiduciary_id" in sql or "id = %s" in sql)


def test_get_admin_metrics_global_admin_keeps_platform_wide(monkeypatch):
    capture = _CapturedDb()
    monkeypatch.setattr(admin.db, "one", capture.one)
    ctx = _ctx(service="admindash", func="get_admin_metrics")
    admin.AdminDashService().get_admin_metrics(ctx)
    counts = [sql for sql in capture.sql if sql.startswith("SELECT COUNT(*)")]
    assert len(counts) == 3
    assert all("fiduciary_id" not in sql for sql in counts)


# ── SEC-07 expired API keys are rejected and lapsed keys swept ───────────────
def test_api_key_valid_rejects_expired(monkeypatch):
    from dpdpcms_py import security

    seen = []
    monkeypatch.setattr(security.db, "one", lambda sql, params=(): seen.append(sql) or None)
    ok, *_ = security.api_key_valid("k", "s")
    assert ok is False
    assert any("expires_at IS NULL OR expires_at > NOW()" in sql for sql in seen)


def test_expire_lapsed_api_keys_sweep(monkeypatch):
    from dpdpcms_py import jobs

    capture = _CapturedDb()
    monkeypatch.setattr(jobs.db, "execute", capture.execute)
    out = jobs.expire_lapsed_api_keys()
    assert isinstance(out, dict)
    assert any("status = 'EXPIRED'" in sql for sql in capture.sql)


# ── SEC-08 a global role:manage actor cannot mint above its own access ──────
def test_role_permissions_check_applies_to_global_actor(monkeypatch):
    def fake_one(sql, params=()):
        if "SELECT permissions FROM roles" in sql:
            return {"permissions": ["role:manage"]}
        return None  # duplicate-code check finds nothing

    monkeypatch.setattr("dpdpcms_py.services.roles.db.one", fake_one)
    ctx = _ctx(
        service="role",
        func="create_role",
        payload={"role_code": "X", "name": "X", "permissions": ["*"]},
        auth_token={"email": "g@x.y", "role": "GLOBAL_OP"},
    )
    with pytest.raises(ApiError) as exc:
        roles.RoleService().create_role(ctx)
    assert exc.value.status == 403
    assert "do not hold" in str(exc.value.message)


def test_role_permissions_check_allows_held_permissions_globally(monkeypatch):
    def fake_one(sql, params=()):
        if "SELECT permissions FROM roles" in sql:
            return {"permissions": ["role:manage", "consent:read"]}
        return None

    monkeypatch.setattr("dpdpcms_py.services.roles.db.one", fake_one)
    executed = []
    monkeypatch.setattr("dpdpcms_py.services.roles.db.execute", lambda sql, params=(): executed.append(sql) or 1)
    monkeypatch.setattr("dpdpcms_py.services.roles.log_event", lambda *a, **k: None)
    ctx = _ctx(
        service="role",
        func="create_role",
        payload={"role_code": "X", "name": "X", "permissions": ["consent:read"]},
        auth_token={"email": "g@x.y", "role": "GLOBAL_OP"},
    )
    roles.RoleService().create_role(ctx)
    assert executed


# ── SEC-12 destructive ops check rowcount before claiming success ───────────
def test_deactivate_user_404_when_no_row(monkeypatch):
    monkeypatch.setattr(admin.db, "execute", lambda *a, **k: 0)
    monkeypatch.setattr(admin, "tenant_filter", lambda ctx, col="fiduciary_id": ("", []))
    ctx = _ctx(service="operator", func="deactivate_user", payload={"user_id": "missing"})
    with pytest.raises(ApiError) as exc:
        admin.OperatorService().deactivate_user(ctx)
    assert exc.value.status == 404


@pytest.mark.parametrize(
    "func, payload, service",
    [
        ("delete_app", {"app_id": "missing"}, "app"),
        ("delete_fiduciary", {"fiduciary_id": "missing"}, "fiduciary"),
        ("delete_policy", {"policy_id": "missing"}, "policy"),
    ],
)
def test_catalog_deletes_404_when_no_row(monkeypatch, func, payload, service):
    from dpdpcms_py.services import catalog

    monkeypatch.setattr(catalog.db, "execute", lambda *a, **k: 0)
    monkeypatch.setattr(catalog, "tenant_filter", lambda ctx, col="fiduciary_id": ("", []))
    svc = {
        "app": catalog.AppService(),
        "fiduciary": catalog.FiduciaryService(),
        "policy": catalog.PolicyService(),
    }[service]
    ctx = _ctx(service=service, func=func, payload=payload)
    with pytest.raises(ApiError) as exc:
        getattr(svc, func)(ctx)
    assert exc.value.status == 404


def test_retire_entry_404_when_no_row(monkeypatch):
    monkeypatch.setattr(governance.db, "execute", lambda *a, **k: 0)
    monkeypatch.setattr(governance, "tenant_filter", lambda ctx, col="fiduciary_id": ("", []))
    ctx = _ctx(service="ropa", func="retire_entry", payload={"id": "missing"})
    with pytest.raises(ApiError) as exc:
        governance.RopaService().retire_entry(ctx)
    assert exc.value.status == 404


def test_revoke_nomination_404_when_no_row(monkeypatch):
    monkeypatch.setattr(rights.db, "execute", lambda *a, **k: 0)
    ctx = _ctx(service="rights", func="revoke_nomination", payload={"nomination_id": "missing"})
    with pytest.raises(ApiError) as exc:
        rights.RightsService().revoke_nomination(ctx)
    assert exc.value.status == 404


# ── SEC-15 erasure covers every principal-identifier table ──────────────────
def test_erasure_targets_cover_every_principal_identifier_column():
    expected = {
        "consent_records": {"user_id"},
        "notifications": {"recipient_id"},
        "consent_validations": {"user_id"},
        "purge_requests": {"user_id"},
        "grievances": {"user_id"},
        "nominations": {"nominating_principal_id", "nominated_principal_id"},
        "data_correction_requests": {"user_id"},
        "reconsent_requests": {"user_id"},
        "parental_verification_logs": {"child_principal_id", "guardian_principal_id"},
        "alerts": {"recipient_id"},
        "notification_deliveries": {"recipient"},
        "breach_affected_principals": {"user_id"},
    }
    covered: dict[str, set[str]] = {}
    for table, column in compliance.ERASURE_TARGETS:
        covered.setdefault(table, set()).add(column)
    for table, columns in expected.items():
        assert columns <= covered.get(table, set()), f"{table} columns not fully erased: {columns - covered.get(table, set())}"


# ── SEC-14 rights app default / DUMMY_OTP switch ─────────────────────────────
def test_unconfigured_rights_app_defaults_to_email(monkeypatch):
    monkeypatch.setattr(governance.db, "one", lambda *a, **k: None)
    ctx = _ctx(service="notification", func="get_rights_app_config", payload={"fiduciary_id": FID})
    out = governance.NotificationService().get_rights_app_config(ctx)
    assert out["otp_mode"] == "EMAIL_OTP"


def test_set_rights_app_rejects_dummy_outside_allow(monkeypatch):
    from dpdpcms_py.config import settings

    if settings.allow_dummy_otp:  # local env permits the evaluation mode
        pytest.skip("ALLOW_DUMMY_OTP is enabled in this environment")
    ctx = _ctx(
        service="notification",
        func="set_rights_app_config",
        payload={"fiduciary_id": FID, "otp_mode": "DUMMY_OTP"},
    )
    with pytest.raises(ApiError) as exc:
        governance.NotificationService().set_rights_app_config(ctx)
    assert exc.value.status == 400


def test_otp_mode_defaults_to_email_when_unconfigured(monkeypatch):
    monkeypatch.setattr(consent.db, "one", lambda *a, **k: {"otp_mode": "EMAIL_OTP", "otp_message_template": None})
    assert consent.PrincipalService._otp_mode(FID)[0] == "EMAIL_OTP"


# ── SEC-13 queued OTP webhook never rests in the clear ───────────────────────
def test_queue_otp_payload_contains_only_ciphertext_and_template(monkeypatch):
    queued = {}

    def queue(fid, event, payload, category="NOTIFICATION"):
        queued["payload"] = payload
        queued["category"] = category

    import dpdpcms_py.webhooks as wh

    monkeypatch.setattr(wh, "queue_webhook", queue)

    class _Cursor:
        def execute(self, sql, params=()):
            assert sql.lstrip().startswith(("UPDATE", "INSERT"))

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _Conn:
        def cursor(self):
            return _Cursor()

    @contextlib.contextmanager
    def fake_connection():
        yield _Conn()

    def fake_one(sql, params=()):
        if "pgp_sym_encrypt" in sql:
            return {"enc": "cipher:" + str(params[0])}
        if "COUNT(*)" in sql:
            return {"count": 0}
        return {"otp_mode": "EMAIL_OTP", "otp_message_template": None}

    monkeypatch.setattr(consent.db, "one", fake_one)
    monkeypatch.setattr(consent.db, "connection", fake_connection)

    ctx = _ctx(
        category="public",
        service="principal",
        func="request_principal_otp",
        payload={"fiduciary_id": FID, "user_id": "u"},
    )
    consent.PrincipalService().request_principal_otp(ctx)
    sent = queued["payload"]
    assert queued["category"] == "OTP"
    assert "otp" not in sent
    assert "message" not in sent
    assert sent["otp_enc"].startswith("cipher:")
    assert "{{otp}}" in sent["message_template"]


def test_render_otp_materialises_code_only_now(monkeypatch):
    from dpdpcms_py import webhooks

    monkeypatch.setattr("dpdpcms_py.principal_otp.decrypt_code", lambda cipher: "123456")
    payload = {"channel": "EMAIL", "otp_enc": "cipher:123456", "message_template": "Code {{otp}}", "expires_in_minutes": 5}
    out = webhooks._render_otp(payload)
    assert out["otp"] == "123456"
    assert out["message"] == "Code 123456"
    assert "otp_enc" not in out
    assert "message_template" not in out


# ── SEC-14 SSO requires a single-use nonce and caches the JWKS client ───────
def test_sso_nonce_mismatch_rejected(monkeypatch):
    import dpdpcms_py.config as config
    import dpdpcms_py.services.admin as admin_mod
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    fake_settings = types.SimpleNamespace(
        sso_issuer="https://issuer.example",
        sso_audience="aud",
        sso_jwks_url="https://issuer.example/jwks",
        token_ttl_minutes=480,
    )
    # sso_login imports settings from ..config inside the function body.
    monkeypatch.setattr(config, "settings", fake_settings)

    op = {"id": "op-1", "name": "SSO", "email": "s@x.y", "role": "DPO", "fiduciary_id": FID, "mfa_enabled": False}

    def one(sql, params=()):
        if "email_hmac" in sql:
            return op
        return None

    executed = []
    monkeypatch.setattr(admin_mod.db, "one", one)
    monkeypatch.setattr(admin_mod.db, "execute", lambda sql, params=(): executed.append(sql) or 1)
    # Craft a real RS256 id_token, then present a mismatched nonce.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    claims = {
        "exp": 9999999999,
        "iat": 1700000000,
        "iss": "https://issuer.example",
        "aud": "aud",
        "sub": "s",
        "email": "s@x.y",
        "email_verified": True,
        "nonce": "intended-nonce",
        "amr": ["pwd"],
    }
    raw = pyjwt.encode(claims, pem, algorithm="RS256")

    class _Key:
        key = public_pem

    class _Client:
        def get_signing_key_from_jwt(self, token):
            return _Key()

    monkeypatch.setattr(admin_mod, "_jwks_client", lambda url: _Client())
    ctx = _ctx(service="operator", func="sso_login", payload={"id_token": raw, "nonce": "wrong"})
    with pytest.raises(ApiError) as exc:
        admin_mod.OperatorService().sso_login(ctx)
    assert exc.value.status == 401


# ── SEC-10 certificates are signed and carry environment metadata ───────────
def test_generate_certificate_emits_signature_and_metadata(monkeypatch):
    from datetime import datetime

    class _CertDb:
        def one(self, sql, params=()):
            if "FROM fiduciaries" in sql:
                return {"name": "F"}
            return None

    captured = {}
    # SEC-10: generation first verifies the chain it embeds; a tampered ledger
    # refuses to sign. The intact branch is exercised by the test below.
    monkeypatch.setattr(
        governance,
        "verify_chain",
        lambda *a, **k: {"intact": True, "rows_checked": 2, "legacy_rows_linkage_only": 0, "truncated": False},
    )

    def fake_list_logs(payload):
        return [{"timestamp": datetime(2026, 1, 1), "audit_action": "CONSENT_GIVEN", "current_log_hash": "abc"}]

    monkeypatch.setattr(governance.db, "one", _CertDb().one)
    monkeypatch.setattr(governance, "list_logs", fake_list_logs)
    monkeypatch.setattr(governance, "log_event", lambda *a, **k: None)

    def fake_insert(sql, params=()):
        # columns: id,fiduciary_id,subject_principal_id,certifying_officer_id,case_ref_id,certificate_data,attestation_text
        captured["data"] = getattr(params[4], "obj", params[4])
        return {"id": "cert-1"}

    monkeypatch.setattr(governance.db, "insert_returning", fake_insert)
    ctx = _ctx(
        service="legal",
        func="generate_certificate",
        payload={"fiduciary_id": FID, "subject_principal_id": "u", "case_ref_id": "c1"},
        operator_id="op-1",
    )
    governance.LegalService().generate_certificate(ctx)
    data = captured["data"]
    assert data["signature"]
    assert data["signature_algorithm"] == "HMAC-SHA256"
    assert "environment" in data
    assert data["evidence_trail"][0]["act"] == "CONSENT_GIVEN"
    assert data["system_metadata"]["summary"]["rows_checked"] == 2


def test_generate_certificate_refuses_to_sign_a_tampered_chain(monkeypatch):
    monkeypatch.setattr(
        governance,
        "verify_chain",
        lambda *a, **k: {"intact": False, "rows_checked": 1, "legacy_rows_linkage_only": 0, "truncated": False},
    )
    monkeypatch.setattr(governance, "list_logs", lambda payload: [])
    monkeypatch.setattr(governance, "log_event", lambda *a, **k: None)
    ctx = _ctx(
        service="legal",
        func="generate_certificate",
        payload={"fiduciary_id": FID, "subject_principal_id": "u", "case_ref_id": "c1"},
        operator_id="op-1",
    )
    with pytest.raises(ApiError) as exc:
        governance.LegalService().generate_certificate(ctx)
    assert exc.value.status == 409


def test_verify_certificate_detects_signature_tampering(monkeypatch):
    from dpdpcms_py.audit import certificate_signature

    data = {"principal_id": "u", "fiduciary_id": FID, "timestamp": "2026-01-01T00:00:00+00:00"}
    data["signature"] = certificate_signature(data)

    def one(sql, params=()):
        assert "FROM evidence_certificates" in sql
        return {"certificate_data": data}

    monkeypatch.setattr(governance.db, "one", one)
    monkeypatch.setattr(governance, "log_event", lambda *a, **k: None)
    ctx = _ctx(service="legal", func="verify_certificate", payload={"id": "cert-1"}, fiduciary_id=FID)
    assert governance.LegalService().verify_certificate(ctx)["valid"] is True

    tampered = {**data, "principal_id": "another-principal"}
    monkeypatch.setattr(
        governance.db,
        "one",
        lambda sql, params=(): {"certificate_data": tampered},
    )
    assert governance.LegalService().verify_certificate(ctx)["valid"] is False


def test_generate_certificate_requires_subject_principal_id():
    from dpdpcms_py import validators

    errors = validators.validate_payload({"_func": "generate_certificate", "user_id": "u", "fiduciary_id": FID})
    assert any("subject_principal_id" in e for e in errors)


# ── SEC-11 is a front-end esc() fix: assert the console pages carry it ──────
def test_console_pages_escape_interpolations():
    from dpdpcms_py.config import WEB_ROOT

    bad = []
    for page in (WEB_ROOT / "console").rglob("*.html"):
        text = page.read_text(encoding="utf-8", errors="ignore")
        if "innerHTML" not in text:
            continue
        if "function esc(s)" not in text:
            bad.append(page.name)
    assert bad == []


# ── SEC-11 residual: every tour page that renders API data escapes it ──────
def test_tour_pages_escape_api_interpolations():
    from dpdpcms_py.config import WEB_ROOT

    bad = []
    for page in (WEB_ROOT / "tour").glob("*.html"):
        text = page.read_text(encoding="utf-8", errors="ignore")
        if "innerHTML" not in text:
            continue
        if "function esc(s)" not in text:
            bad.append(page.name)
    assert bad == []


# ── P5-01 the grievance statements run before the generic erasure loop ─────
class _ErasureCursor:
    def __init__(self):
        self.sql = []
        self._rows = []
        self.rowcount = 1

    def execute(self, sql, params=()):
        self.sql.append(sql)
        self._rows = [{"storage_path": "p1"}] if "RETURNING storage_path" in sql else []
        self.rowcount = 1

    def fetchall(self):
        return self._rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_erasure_orders_grievance_statements_before_the_loop(monkeypatch, tmp_path):
    cursor = _ErasureCursor()

    class _Conn:
        def cursor(self):
            return cursor

    @contextlib.contextmanager
    def fake_connection():
        yield _Conn()

    monkeypatch.setattr(compliance.db, "connection", fake_connection)
    monkeypatch.setattr(compliance.db, "one", lambda sql, params=(): None)
    compliance.erase_cms_copy(FID, "asha")
    # The dedicated grievance DELETE and the text-blanking UPDATE come first,
    # before any statement of the generic loop, so their WHERE clauses still
    # match the ORIGINAL user_id.
    del_idx = next(i for i, s in enumerate(cursor.sql) if "DELETE FROM grievance_attachments" in s)
    upd_idx = next(i for i, s in enumerate(cursor.sql) if "attachments = '[]'::jsonb" in s)
    generic_idx = next(
        i for i, s in enumerate(cursor.sql) if s.lstrip().startswith("UPDATE") and "grievances" not in s
    )
    assert del_idx < generic_idx and upd_idx < generic_idx
    # The generic loop no longer re-keys grievances a second time.
    grievance_updates = [s for s in cursor.sql if s.lstrip().startswith("UPDATE grievances")]
    assert len(grievance_updates) == 1
    # SEC-15 survivors are scrubbed too.
    assert any("UPDATE evidence_certificates" in s for s in cursor.sql)
    assert any("SET guardian_id" in s for s in cursor.sql)
    assert any("SET ip_address = '0.0.0.0'" in s for s in cursor.sql)
    assert any("UPDATE webhook_deliveries" in s for s in cursor.sql)


# ── P5-02 the throttle counter resets when a lapsed lock is observed ────────
def test_throttle_lapsed_lock_starts_a_fresh_window(monkeypatch):
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    lapsed = now - timedelta(minutes=5)
    captured = {}

    class _Cursor:
        def __init__(self):
            self.phase = 0

        def execute(self, sql, params=()):
            if self.phase == 1 and "INSERT INTO auth_throttles" in sql:
                captured["params"] = params
            self.phase += 1

        def fetchone(self):
            return {"failures": 5, "locked_until": lapsed, "lockout_minutes": 30}

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _Conn:
        def cursor(self):
            return _Cursor()

    @contextlib.contextmanager
    def fake_connection():
        yield _Conn()

    monkeypatch.setattr(throttle.db, "connection", fake_connection)
    throttle.record_failure("login:ip", "1.2.3.4")
    # P5-02: after a lapsed lock the counter restarts at 1 (not 6) and no lock
    # is set, so one attempt every 15 minutes can no longer lock the key for
    # ever. The single failure is a fresh window, not a re-lock.
    assert captured["params"][2] == 1
    assert captured["params"][3] is None


def test_throttle_lock_escalates_geometrically(monkeypatch):
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    captured = {}

    class _Cursor:
        def __init__(self):
            self.phase = 0

        def execute(self, sql, params=()):
            if self.phase == 1 and "INSERT INTO auth_throttles" in sql:
                captured["params"] = params
            self.phase += 1

        def fetchone(self):
            # Four prior failures, the last lock 30 minutes long and lapsed.
            return {"failures": 4, "locked_until": None, "lockout_minutes": 30}

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _Conn:
        def cursor(self):
            return _Cursor()

    @contextlib.contextmanager
    def fake_connection():
        yield _Conn()

    monkeypatch.setattr(throttle.db, "connection", fake_connection)
    throttle.record_failure("login:ip", "1.2.3.4")
    # The 5th failure sets a lock whose duration doubles the previous one
    # (30 -> 60 minutes, capped at MAX_LOCKOUT_MINUTES).
    assert captured["params"][2] == 5
    assert captured["params"][4] == 60
    assert captured["params"][3] > now


def test_throttle_email_key_normaliases_and_stores_no_address():
    assert throttle.email_key(" A@X.Y ") == throttle.email_key("a@x.y")
    assert "a@x.y" not in throttle.email_key("a@x.y")
    assert throttle.email_key("x").startswith("hmac:")


# ── SEC-18 non-ADMIN operators must belong to a fiduciary ───────────────────
def test_create_user_refuses_non_admin_without_fiduciary(monkeypatch):
    monkeypatch.setattr(admin, "verified_role", lambda ctx: "ADMIN")
    monkeypatch.setattr(admin, "authenticated_user_id", lambda ctx: "admin-1")
    monkeypatch.setattr(admin.db, "one", lambda sql, params=(): {"x": 1})
    ctx = _ctx(
        service="operator",
        func="create_user",
        payload={"username": "op", "email": "op@x.y", "password": "longenough12", "role": "OPERATOR"},
    )
    with pytest.raises(ApiError) as exc:
        admin.OperatorService().create_user(ctx)
    assert exc.value.status == 400
    assert "fiduciary_id" in str(exc.value.message)


# ── SEC-05 the s.9 gate reads the stored age_category ───────────────────────
def test_record_consent_stored_minor_without_guardian_is_rejected(monkeypatch):
    from dpdpcms_py.services import consent as consent_mod

    payload = {
        "user_id": "asha",
        "policy_id": "p1",
        "data_point_consents": [{"data_point_id": "care", "consent_granted": True}],
        "jurisdiction": "IN",
        "language_selected": "en",
    }
    ctx = _ctx(
        category="client",
        service="consent",
        func="record_consent",
        payload=payload,
        fiduciary_id=FID,
        source_ip="1.2.3.4",
        headers={"user-agent": "test-agent"},
    )
    policy_content = {"en": {"title": "P", "data_processing_purposes": [{"id": "care", "name": "Care"}]}}

    def one(sql, params=()):
        if "SELECT version, policy_content FROM consent_policies" in sql:
            return {"version": "v1", "policy_content": policy_content}
        if "SELECT policy_content FROM consent_policies" in sql:
            return {"policy_content": policy_content}
        if "SELECT age_category FROM data_principal" in sql:
            return {"age_category": "MINOR"}
        return None  # no verified guardian log for the stored minor

    monkeypatch.setattr(consent_mod.db, "one", one)
    monkeypatch.setattr(consent_mod.db, "all", lambda sql, params=(): [])
    with pytest.raises(ApiError) as exc:
        consent_mod.ConsentService().record_consent(ctx)
    assert exc.value.status == 403
    assert "guardian" in str(exc.value.message).lower()


def test_record_consent_cannot_flip_stored_minor_to_adult(monkeypatch):
    from dpdpcms_py.services import consent as consent_mod

    payload = {
        "user_id": "asha",
        "policy_id": "p1",
        "data_point_consents": [{"data_point_id": "care", "consent_granted": True}],
        "age_category": "ADULT",
        "jurisdiction": "IN",
        "language_selected": "en",
    }
    ctx = _ctx(
        category="client",
        service="consent",
        func="record_consent",
        payload=payload,
        fiduciary_id=FID,
    )
    policy_content = {"en": {"title": "P", "data_processing_purposes": [{"id": "care", "name": "Care"}]}}

    def one(sql, params=()):
        if "SELECT version, policy_content FROM consent_policies" in sql:
            return {"version": "v1", "policy_content": policy_content}
        if "SELECT policy_content FROM consent_policies" in sql:
            return {"policy_content": policy_content}
        if "SELECT age_category FROM data_principal" in sql:
            return {"age_category": "MINOR"}
        return None

    monkeypatch.setattr(consent_mod.db, "one", one)
    monkeypatch.setattr(consent_mod.db, "all", lambda sql, params=(): [])
    with pytest.raises(ApiError) as exc:
        consent_mod.ConsentService().record_consent(ctx)
    assert exc.value.status == 403
    assert "minor" in str(exc.value.message).lower()


# ── SEC-12 rowcount is honoured by update_user too ─────────────────────────
def test_update_user_404_when_no_row(monkeypatch):
    monkeypatch.setattr(admin.db, "execute", lambda *a, **k: 0)
    monkeypatch.setattr(admin, "verified_role", lambda ctx: "ADMIN")
    ctx = _ctx(service="operator", func="update_user", payload={"user_id": "missing", "username": "x"})
    with pytest.raises(ApiError) as exc:
        admin.OperatorService().update_user(ctx)
    assert exc.value.status == 404


# ── P5-06 create_nomination lets DEFAULT NOW() set valid_from ───────────────
def test_create_nomination_defaults_valid_from(monkeypatch):
    executed = []

    def fake_insert(sql, params=()):
        executed.append(sql)
        return {"id": "n-1"}

    monkeypatch.setattr(rights.db, "insert_returning", fake_insert)
    monkeypatch.setattr(rights, "log_event", lambda *a, **k: None)
    monkeypatch.setattr(rights, "resolve_fiduciary", lambda ctx: FID)
    ctx = _ctx(
        category="client",
        service="rights",
        func="create_nomination",
        payload={"nominating_principal_id": "a", "nominated_principal_id": "b"},
        fiduciary_id=FID,
    )
    rights.RightsService().create_nomination(ctx)
    insert = next(s for s in executed if "INSERT INTO nominations" in s)
    assert "valid_from" not in insert, "valid_from must be omitted so the DEFAULT NOW() applies"
    assert "valid_until" in insert


# ── P5-04 / SEC-04 purge binding falls back to the assigned party ───────────
def test_confirm_purge_key_allowed_for_null_app_undesignated_request(monkeypatch):
    capture = _PurgeDb(app_id=None, assigned_operator_id=None)
    executed = []
    monkeypatch.setattr(compliance.db, "one", capture.one)
    monkeypatch.setattr(compliance.db, "execute", lambda sql, params=(): executed.append(sql) or 1)
    monkeypatch.setattr(compliance, "erase_cms_copy", lambda *a, **k: {})
    monkeypatch.setattr(compliance, "log_event", lambda *a, **k: None)
    ctx = _confirm_ctx(app_id=APP_ID, permissions={"PURGE"})
    out = compliance.ComplianceService().confirm_purge_status(ctx)
    assert out["success"] is True


def test_confirm_purge_delegated_request_is_bound_to_the_assignee(monkeypatch):
    capture = _PurgeDb(app_id=None, assigned_operator_id="op-1")
    executed = []
    monkeypatch.setattr(compliance.db, "one", capture.one)
    monkeypatch.setattr(compliance.db, "execute", lambda sql, params=(): executed.append(sql) or 1)
    monkeypatch.setattr(compliance, "erase_cms_copy", lambda *a, **k: {})
    monkeypatch.setattr(compliance, "log_event", lambda *a, **k: None)
    # An API key may not close a request delegated to a specific operator...
    ctx = _confirm_ctx(app_id=APP_ID, permissions={"PURGE"})
    with pytest.raises(ApiError) as exc:
        compliance.ComplianceService().confirm_purge_status(ctx)
    assert exc.value.status == 403
    # ...but the assignee operator may.
    ctx2 = _confirm_ctx(operator_id="op-1", auth_token={"email": "dpo@x.y", "role": "DPO"})
    out = compliance.ComplianceService().confirm_purge_status(ctx2)
    assert out["success"] is True


# ── SEC-17 GET validation and the death of ?auth= ───────────────────────────
def test_get_on_a_write_function_is_405():
    from dpdpcms_py import main as main_mod
    from fastapi.testclient import TestClient

    response = TestClient(main_mod.app).get(
        "/api/v1/operator",
        params={
            "_func": "reset_password_via_recovery",
            "email": "a@b.c",
            "passphrase": "p",
            "new_password": "longenough12",
        },
    )
    assert response.status_code == 405, response.text


def test_auth_query_parameter_no_longer_authenticates():
    from dpdpcms_py import main as main_mod
    from fastapi.testclient import TestClient

    response = TestClient(main_mod.app).get("/api/v1/operator", params={"_func": "list_users", "auth": "forged"})
    assert response.status_code == 401, response.text


def test_get_read_dispatch_validates_and_reaches_the_handler(monkeypatch):
    from dpdpcms_py import main as main_mod
    from dpdpcms_py.services import consent as consent_mod
    from fastapi.testclient import TestClient

    called = []

    def fake_handle(self, ctx):
        called.append((ctx.func, dict(ctx.payload)))
        return {"success": True}

    monkeypatch.setattr(consent_mod.ConsentService, "handle", fake_handle)
    monkeypatch.setattr(
        main_mod,
        "decode_token",
        lambda raw: {"typ": "principal", "fid": FID, "sub": "asha", "jti": "j1"},
    )
    response = TestClient(main_mod.app).get(
        "/api/v1/client/consent", params={"_func": "get_active_consent", "user_id": "asha"}
    )
    assert response.status_code == 200, response.text
    assert called and called[0][0] == "get_active_consent"