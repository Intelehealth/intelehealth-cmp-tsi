"""Regression tests for the defects raised in MeitY_BRD_API_Traceability_v5.xlsx
("Defect Remediation" sheet): P4-01 wallet validation order, P4-02 fail-open
schema lookup, CF-01 WEB-INF exposure, D11 default-deny role classifier.

Requests go through the real FastAPI dispatch path; the service methods and
credential checks are monkeypatched, so no database is needed.
"""

import pytest
from dpdpcms_py import main, validators
from dpdpcms_py.security import principal_token
from dpdpcms_py.services import consent, roles
from fastapi.testclient import TestClient

FID = "11111111-1111-1111-1111-111111111111"
USER = "principal-42"


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture
def ran(monkeypatch):
    """Record which ConsentService / PolicyService function a request reached."""
    from dpdpcms_py.services import catalog

    calls = []

    def fake(name):
        return lambda self, ctx: calls.append((name, dict(ctx.payload))) or {"success": True}

    for name in ("record_consent", "erasure_request", "get_consent_record_details"):
        monkeypatch.setattr(consent.ConsentService, name, fake(name))
    monkeypatch.setattr(catalog.PolicyService, "get_active_policy", fake("get_active_policy"))
    return calls


def _wallet(client, body, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post("/api/v1/client/wallet", json=body, headers=headers)


# ── P4-01 wallet payloads validate once token fields are bound ─────────────
@pytest.mark.parametrize(
    "body, target",
    [
        ({"action": "GLOBAL_ERASURE"}, "erasure_request"),
        ({"action": "REVOKE_PURPOSE", "purpose_id": "p1"}, "erasure_request"),
        ({"action": "GRANT_CONSENT", "policy_id": "pol", "data_point_consents": []}, "record_consent"),
        ({"action": "GET_CONSENT_DETAILS", "record_id": "r1"}, "get_consent_record_details"),
        ({"action": "GET_POLICY_PURPOSES", "jurisdiction": "IN"}, "get_active_policy"),
    ],
)
def test_wallet_actions_reachable_with_principal_token(client, ran, body, target):
    response = _wallet(client, body, principal_token(FID, USER))
    assert response.status_code in (200, 201), response.text
    name, payload = ran[-1]
    assert name == target
    assert payload["fiduciary_id"] == FID
    assert payload["user_id"] == USER


def test_wallet_client_command_field_is_accepted(client, ran):
    response = _wallet(client, {"command": "GLOBAL_ERASURE"}, principal_token(FID, USER))
    assert response.status_code == 200, response.text
    assert ran[-1][0] == "erasure_request"


def test_wallet_still_validates_target_schema(client, ran):
    # GRANT_CONSENT without policy_id must be refused by record_consent's schema.
    response = _wallet(client, {"action": "GRANT_CONSENT"}, principal_token(FID, USER))
    assert response.status_code == 400
    assert "policy_id" in response.json()["message"]
    assert ran == []


def test_wallet_principal_cannot_act_for_another_user(client, ran):
    response = _wallet(client, {"action": "GLOBAL_ERASURE", "user_id": "someone-else"}, principal_token(FID, USER))
    assert response.status_code == 403
    assert ran == []


def test_wallet_api_key_caller_must_name_user(client, ran, monkeypatch):
    monkeypatch.setattr(main, "api_key_valid", lambda *a: (True, FID, {"READ", "WRITE", "PURGE"}, None))
    response = _wallet(client, {"action": "GLOBAL_ERASURE"})
    assert response.status_code == 400
    assert "user_id" in response.json()["message"]
    response = _wallet(client, {"action": "GLOBAL_ERASURE", "user_id": USER})
    assert response.status_code == 200, response.text


# ── P4-02 schema lookup is case-insensitive and fails closed ───────────────
@pytest.mark.parametrize("func", ["erasure_request", "Erasure_Request", "ERASURE_REQUEST", " erasure_request "])
def test_schema_lookup_ignores_case(func):
    assert validators.validate_payload({"_func": func}) == ["'user_id' is a required property"]


@pytest.mark.parametrize("func", ["no_such_function", "../config", "erasure_request.jschema", "érasure"])
def test_unknown_function_fails_closed(func):
    assert validators.validate_payload({"_func": func}) == [f"Unsupported function: {func.strip().lower()}"]


def test_every_api_function_has_a_schema():
    import inspect

    from dpdpcms_py.services import SERVICE_REGISTRY

    missing = sorted(
        name
        for cls in SERVICE_REGISTRY.values()
        for name, _ in inspect.getmembers(cls, inspect.isfunction)
        if not name.startswith("_") and name != "handle" and validators._validator(name) is None
    )
    assert missing == []


def test_mixed_case_func_validated_over_http(client, ran):
    response = _wallet(client, {"_func": "Erasure_Request"}, None)
    # Normalised before auth and validation: no API key, so 401, never a bypass.
    assert response.status_code == 401
    assert ran == []


# ── CF-01 WEB-INF is never served ──────────────────────────────────────────
@pytest.mark.parametrize(
    "path",
    [
        "/WEB-INF/validator/erasure_request.jschema",
        "/web-inf/validator/erasure_request.jschema",
        "/WEB-INF/",
        "/console/../WEB-INF/validator/erasure_request.jschema",
        "/WEB-INF./validator/erasure_request.jschema",
    ],
)
def test_web_inf_not_served(client, path):
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 404
    assert "required" not in response.text


def test_static_pages_still_served(client):
    assert client.get("/").status_code == 200


# ── D11 default branch: an unrecognised verb is a write ────────────────────
@pytest.mark.parametrize("func", ["confirm_thing", "approve_request", "frobnicate", "check_status", "readme"])
def test_unknown_verb_defaults_to_write(func):
    assert roles.required_permission("consent", func) == "consent:write"


def test_read_prefixes_are_the_closed_set():
    assert roles.READ_PREFIXES == ("list_", "get_", "download_", "export_")
