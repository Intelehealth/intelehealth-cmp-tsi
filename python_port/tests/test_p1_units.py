"""Unit tests for the P1 build-out — pure logic only, no database required.

Exercises the SSRF guard, the webhook HMAC signing, and the purpose-lifecycle
duration-flag validation. Integration behaviour (end-to-end against Postgres)
is covered by the manual test script referenced in dpdpcms_py/../README.md.
"""

import socket

import pytest
from dpdpcms_py import netutil
from dpdpcms_py.context import RequestContext
from dpdpcms_py.errors import ApiError
from dpdpcms_py.services.base import (
    bind_principal_field,
    ensure_principal_owns,
    principal_list_filter,
    reject_principal,
)
from dpdpcms_py.services.lifecycle import extract_purposes, validate_duration_flags
from dpdpcms_py.webhooks import _sign


# ── SSRF guard (netutil.validate_outbound_url) ────────────────────────
def test_rejects_loopback():
    with pytest.raises(ValueError):
        netutil.validate_outbound_url("http://127.0.0.1/evil", "webhook_url")


def test_rejects_private_and_link_local():
    for host in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1", "::1", "fc00::1"):
        with pytest.raises(ValueError):
            netutil.validate_outbound_url(f"https://{host}/x")


def test_rejects_bad_scheme_and_embedded_credentials():
    with pytest.raises(ValueError):
        netutil.validate_outbound_url("ftp://host/path")
    with pytest.raises(ValueError):
        netutil.validate_outbound_url("http://user:pass@host/path")


def test_rejects_hostname_resolving_to_private(monkeypatch):
    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(netutil.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ValueError):
        netutil.validate_outbound_url("https://evil.example.com/hook")


def test_accepts_public_hostname(monkeypatch):
    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(netutil.socket, "getaddrinfo", fake_getaddrinfo)
    assert netutil.validate_outbound_url("https://example.com/hook") == "https://example.com/hook"


# ── Webhook HMAC signing ─────────────────────────────────────────────
def test_signature_format_and_determinism():
    first = _sign("shared-secret", b"hello world")
    second = _sign("shared-secret", b"hello world")
    other = _sign("shared-secret", b"hello worle")
    assert first.startswith("sha256=")
    assert first == second
    assert first != other


# ── Purpose lifecycle duration flags (PL-01) ─────────────────────────
def test_extract_purposes_dedupes_across_languages():
    content = {
        "en": {"data_processing_purposes": [{"id": "p1", "name": "English"}]},
        "hi": {"data_processing_purposes": [{"id": "p1", "name": "Hindi"}]},
    }
    purposes = extract_purposes(content)
    assert [p["id"] for p in purposes] == ["p1"]


def test_open_ended_flag_accepted():
    validate_duration_flags({"en": {"data_processing_purposes": [{"id": "p1", "duration_type": "OPEN_ENDED"}]}})


def test_missing_duration_flag_rejected():
    with pytest.raises(ApiError):
        validate_duration_flags({"en": {"data_processing_purposes": [{"id": "p1"}]}})


def test_time_bound_without_expiry_rejected():
    with pytest.raises(ApiError):
        validate_duration_flags({"en": {"data_processing_purposes": [{"id": "p1", "duration_type": "TIME_BOUND"}]}})
    with pytest.raises(ApiError):
        validate_duration_flags(
            {
                "en": {
                    "data_processing_purposes": [{"id": "p1", "duration_type": "TIME_BOUND", "consent_expiry_days": 0}]
                }
            }
        )


def test_time_bound_with_expiry_accepted():
    validate_duration_flags(
        {"en": {"data_processing_purposes": [{"id": "p1", "duration_type": "TIME_BOUND", "consent_expiry_days": 30}]}}
    )


def _principal_ctx(**payload: str) -> RequestContext:
    return RequestContext(
        path="/api/v1/client/rights",
        category="client",
        service="rights",
        payload=dict(payload),
        headers={},
        method="POST",
        principal_user_id="user-abc",
        auth_via_principal_jwt=True,
    )


def test_bind_principal_field_sets_user_id():
    ctx = _principal_ctx()
    bind_principal_field(ctx, "user_id")
    assert ctx.payload["user_id"] == "user-abc"


def test_bind_principal_field_rejects_mismatch():
    ctx = _principal_ctx(user_id="other-user")
    with pytest.raises(ApiError) as exc:
        bind_principal_field(ctx, "user_id")
    assert exc.value.status == 403


def test_principal_list_filter_scopes_lists():
    ctx = _principal_ctx()
    assert principal_list_filter(ctx, "user_id") == "user-abc"


def test_reject_principal_blocks_notify_style_calls():
    ctx = _principal_ctx()
    with pytest.raises(ApiError):
        reject_principal(ctx)


def test_ensure_principal_owns_rejects_other_users():
    ctx = _principal_ctx()
    with pytest.raises(ApiError) as exc:
        ensure_principal_owns(ctx, "someone-else", label="Grievance")
    assert exc.value.status == 404


def test_ensure_principal_owns_noop_for_api_key_sessions():
    ctx = RequestContext(
        path="/api/v1/client/consent",
        category="client",
        service="consent",
        payload={},
        headers={},
        method="POST",
        auth_via_principal_jwt=False,
    )
    ensure_principal_owns(ctx, "anyone")
