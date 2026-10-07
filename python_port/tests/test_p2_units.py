"""Unit tests for the P2 build-out — pure logic only, no database required.

Exercises the TOTP primitive (SA-06), the retention-duration arithmetic with its
statutory floor (SA-08/SA-12), and the role-permission gate (SA-01/SA-02/LG-06).
"""

import pytest
from dpdpcms_py import totp
from dpdpcms_py.context import RequestContext
from dpdpcms_py.errors import ApiError
from dpdpcms_py.services.retention import STATUTORY_FLOOR_DAYS, retention_duration_days
from dpdpcms_py.services.roles import require_audit_access, require_permission


def _ctx(role: str | None = "ADMIN", mfa: bool | None = None) -> RequestContext:
    auth = {"role": role}
    if mfa is not None:
        auth["mfa"] = mfa
    return RequestContext(
        path="/api/v1/admin/audit",
        category="admin",
        service="audit",
        payload={},
        headers={},
        method="POST",
        auth_token=auth,
    )


# ── TOTP (SA-06) ─────────────────────────────────────────────────
def test_generate_secret_shape():
    secret = totp.generate_secret()
    assert len(secret) == 32
    assert set(secret) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def test_totp_is_6_digits_and_deterministic():
    secret = totp.generate_secret()
    code = totp.totp_at(secret, 1_700_000_000.0)
    assert len(code) == 6 and code.isdigit()
    assert totp.totp_at(secret, 1_700_000_000.0) == code


def test_verify_accepts_fresh_and_rejects_wrong_code():
    secret = totp.generate_secret()
    now = 1_700_000_000.0
    good = totp.totp_at(secret, now)
    assert totp.verify_totp(secret, good, now)
    assert not totp.verify_totp(secret, "123456", now)


def test_verify_allows_small_drift_window():
    secret = totp.generate_secret()
    now = 1_700_000_000.0
    next_step = totp.totp_at(secret, now + totp.DEFAULT_STEP_SECONDS)
    assert totp.verify_totp(secret, next_step, now)


def test_otpauth_uri_is_provisioning_shaped():
    uri = totp.otpauth_uri(totp.generate_secret(), "dpo@example.com")
    assert uri.startswith("otpauth://")
    assert "secret=" in uri and "issuer=" in uri


# ── Retention durations (SA-08 / SA-12) ──────────────────────────
def test_retention_days_conversion():
    assert retention_duration_days(3, "YEARS") == 1095
    assert retention_duration_days(12, "MONTHS") == 360
    assert retention_duration_days(30, "DAYS") == 30


def test_retention_rejects_non_positive():
    for value in (0, -10, "abc", None):
        with pytest.raises(ApiError):
            retention_duration_days(value, "DAYS")


def test_retention_rejects_bad_unit():
    with pytest.raises(ApiError):
        retention_duration_days(10, "FORTNIGHTS")


def test_statutory_floor_is_seven_years():
    assert STATUTORY_FLOOR_DAYS == 2555


def test_retention_service_rejects_below_floor_without_db():
    from dpdpcms_py.services.retention import RetentionService

    svc = RetentionService()
    # 6 years is below the 7-year floor -> rejected before any SQL runs.
    with pytest.raises(ApiError) as exc:
        svc._apply(
            {"name": "Nursing records", "retention_duration_value": 6, "retention_duration_unit": "YEARS"},
            "00000000-0000-0000-0000-000000000000",
        )
    assert exc.value.status == 400
    assert "statutory floor" in str(exc.value.message)


# ── Role permission gate (SA-01/SA-02, LG-06) ────────────────────
def test_admin_has_full_access():
    ctx = _ctx("ADMIN")
    require_permission(ctx, "audit:read")  # must not raise
    require_permission(ctx, "retention:write")  # must not raise


def test_unknown_role_is_denied(monkeypatch):
    ctx = _ctx("OPERATOR")
    # No AUDIT-READ for OPERATOR in the seeded role table.
    monkeypatch.setattr("dpdpcms_py.services.roles.db.one", lambda *a, **k: {"permissions": ["consent:read"]})
    with pytest.raises(ApiError) as exc:
        require_permission(ctx, "audit:read")
    assert exc.value.status == 403


def test_audit_gate_requires_verified_mfa(monkeypatch):
    # AUDITOR has audit:read in the seeded role table, but the token is not
    # MFA-verified, so reading audit logs is refused (LG-06).
    monkeypatch.setattr("dpdpcms_py.services.roles.db.one", lambda *a, **k: {"permissions": ["audit:read"]})
    with pytest.raises(ApiError) as exc:
        require_audit_access(_ctx("AUDITOR", mfa=False))
    assert exc.value.status == 403


def test_audit_gate_passes_when_mfa_verified(monkeypatch):
    monkeypatch.setattr("dpdpcms_py.services.roles.db.one", lambda *a, **k: {"permissions": ["audit:read"]})
    require_audit_access(_ctx("AUDITOR", mfa=True))  # must not raise