"""CMP API test run e01db1 regressions (TC-N-13, TC-39/TC-N-19, MFA enrolment).

DB-backed tests reuse the transaction-per-test fixture and seed helpers of
test_integration_db.py and skip without a live Postgres; the rest are unit
tests.
"""

import pytest
from dpdpcms_py import totp
from tests.test_defect_fixes import SECRET, _verify, operator_row  # noqa: F401 - fixture
from tests.test_integration_db import _DB_READY, _seed_consent, _seed_tenant
from tests.test_pii_port import _bearer, _console, _reveal_operator

needs_db = pytest.mark.skipif(not _DB_READY, reason="no live Postgres configured")


# ---- TC-N-13: a policy purpose's legal_basis is one of the ROPA bases ---------------------


def _policy_payload(func, legal_basis):
    purpose = {"id": "care", "name": "Care", "legal_basis": legal_basis}
    return {"_func": func, "policy_id": "p", "policy_content": {"en": {"data_processing_purposes": [purpose]}}}


@pytest.mark.parametrize("func", ["create_policy", "update_policy"])
@pytest.mark.parametrize(
    ("legal_basis", "ok"),
    [
        ("consent", True),
        ("legal_obligation", True),
        ("vital_interest", True),
        ("legitimate_use", True),
        ("marketing", False),
        ("Consent", False),
    ],
)
def test_policy_schema_refuses_unknown_legal_basis(func, legal_basis, ok):
    from dpdpcms_py.validators import validate_payload

    errors = [e for e in validate_payload(_policy_payload(func, legal_basis)) if "is not one of" in e]
    assert (errors == []) is ok


# ---- MFA: sessions issued before enrolment are revoked when MFA is turned on -------------


def test_verify_mfa_revokes_sessions_issued_before_enrolment(operator_row, monkeypatch):  # noqa: F811
    from dpdpcms_py.services import admin

    seen = []
    real_execute = admin.db.execute

    def execute(sql, params=()):
        seen.append(sql)
        return real_execute(sql, params)

    monkeypatch.setattr(admin.db, "execute", execute)
    assert _verify(totp.totp_at(SECRET))["mfa"] is True
    [enable] = [s for s in seen if "mfa_enabled = TRUE" in s]
    # Only the first enrolment moves the cut-off: a later MFA sign-in leaves other sessions alone.
    assert "tokens_valid_after = CASE WHEN mfa_enabled THEN tokens_valid_after ELSE NOW() END" in enable


# ---- TC-39/TC-N-19: the principal gets a handle on each purge request ---------------------


@needs_db
def test_erasure_request_returns_its_purge_requests(tx):
    with tx.cursor() as cur:
        fid, pol = _seed_tenant(cur)
        _seed_consent(cur, fid, pol, "asha")
        _, email = _reveal_operator(cur, fid, "DPO", "dee")
    payload = {"user_id": "asha", "fiduciary_id": fid, "reason": "Principal asked by phone on 20 Oct"}
    response = _console(_bearer(email, "DPO"), "erasure_request", payload)
    assert response.status_code == 200, response.text
    [purge] = response.json()["purge_requests"]
    with tx.cursor() as cur:
        cur.execute("SELECT id, status, purpose_id FROM purge_requests WHERE fiduciary_id = %s", (fid,))
        [row] = cur.fetchall()
    assert purge["purge_request_id"] == str(row["id"])
    assert purge["status"] == row["status"] == "PENDING"
    assert purge["purpose_id"] == row["purpose_id"]
    assert purge["hold_until"] is None
