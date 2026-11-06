"""Review P17 regressions: operator-only admin tokens (P17-02), TSI_BOOTSTRAP_TOKEN
(P17-04), placeholder secrets outside local (P17-06), the login throttle on the
OTP endpoints (P17-08) and a 401 for a malformed API key (P17-09).

No database: the db and throttle helpers are monkeypatched with small fakes.
"""

import time
import uuid

import jwt
import pytest
from dpdpcms_py import config, main, principal_otp, security
from dpdpcms_py.config import settings
from dpdpcms_py.errors import ApiError
from dpdpcms_py.services import consent
from fastapi.testclient import TestClient
from tests.test_defect_fixes import FID, _ctx, otp_store  # noqa: F401 (fixture)

# ---- P17-02: the admin API accepts operator tokens only ------------------------------------


def _claims(**extra):
    now = int(time.time())
    return {
        "sub": "dpo@x.y",
        "email": "dpo@x.y",
        "role": "DPO",
        "iat": now,
        "exp": now + 3600,
        "jti": str(uuid.uuid4()),
        "mfa": True,
        **extra,
    }


def test_operator_tokens_are_typed():
    assert jwt.decode(security.token("a@x.y", "A", "DPO"), options={"verify_signature": False})["typ"] == "operator"
    principal = jwt.decode(security.principal_token(FID, "asha"), options={"verify_signature": False})
    assert principal["typ"] == "principal"


@pytest.mark.parametrize(
    "claims, expected",
    [
        (_claims(typ="operator"), True),
        (_claims(typ="principal"), False),
        (_claims(typ="service"), False),
        (_claims(typ="operator", email=""), False),
        # An untyped token minted after start-up is not a legacy session.
        (_claims(), False),
        # An untyped token issued before start-up is a pre-upgrade session.
        (_claims(iat=security.UNTYPED_TOKEN_CUTOFF - 60), True),
    ],
)
def test_is_operator_token(claims, expected):
    assert security.is_operator_token(claims) is expected


@pytest.mark.parametrize("typ", ["principal", "service", None])
def test_admin_api_refuses_non_operator_tokens(monkeypatch, typ):
    looked_up = []
    monkeypatch.setattr(main.db, "one", lambda *a, **k: looked_up.append(a) or None)
    extra = {"typ": typ} if typ else {}
    raw = jwt.encode(_claims(**extra), settings.jwt_secret, algorithm="HS256")
    response = TestClient(main.app).post(
        "/api/v1/admin/operator", json={"_func": "list_users"}, headers={"Authorization": f"Bearer {raw}"}
    )
    assert response.status_code == 401, response.text
    assert not looked_up  # refused before the operator lookup


# ---- P17-04 / P17-06: bootstrap token name and placeholder secrets -------------------------

GOOD = "0123456789abcdef0123456789abcdef"


def test_tsi_bootstrap_token_is_read_first(monkeypatch):
    monkeypatch.setenv("TSI_BOOTSTRAP_TOKEN", GOOD)
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "f" * 32)
    assert config._secret("TSI_BOOTSTRAP_TOKEN", fallback="BOOTSTRAP_TOKEN") == GOOD


def test_bootstrap_token_falls_back_to_the_old_name(monkeypatch):
    monkeypatch.delenv("TSI_BOOTSTRAP_TOKEN", raising=False)
    monkeypatch.setenv("BOOTSTRAP_TOKEN", GOOD)
    assert config._secret("TSI_BOOTSTRAP_TOKEN", fallback="BOOTSTRAP_TOKEN") == GOOD


def test_missing_bootstrap_token_names_the_new_variable(monkeypatch):
    monkeypatch.delenv("TSI_BOOTSTRAP_TOKEN", raising=False)
    monkeypatch.delenv("BOOTSTRAP_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="TSI_BOOTSTRAP_TOKEN"):
        config._secret("TSI_BOOTSTRAP_TOKEN", fallback="BOOTSTRAP_TOKEN")


COMPOSE_DEFAULTS = [
    "tsi-dpdp-cms-local-dev-secret-do-not-use-in-production",
    "local-dev-enc-key-do-not-use-in-production",
    "local-dev-lookup-salt-do-not-use-in-production",
    "local-dev-bootstrap-token-do-not-use-in-production",
]


@pytest.mark.parametrize("env", ["test", "staging", "production", "Production"])
@pytest.mark.parametrize("value", COMPOSE_DEFAULTS)
def test_placeholder_secrets_refused_outside_local(monkeypatch, env, value):
    monkeypatch.setenv("TSI_DPDP_CMS_ENV", env)
    monkeypatch.setenv("JWT_SECRET", value)
    with pytest.raises(RuntimeError, match="development default"):
        config._secret("JWT_SECRET")


def test_compose_database_password_refused_outside_local(monkeypatch):
    monkeypatch.setenv("TSI_DPDP_CMS_ENV", "staging")
    monkeypatch.setenv("POSTGRES_PASSWD", "secure_dev_password")
    with pytest.raises(RuntimeError, match="development default"):
        config._secret("POSTGRES_PASSWD", minimum=8)


@pytest.mark.parametrize("value", COMPOSE_DEFAULTS)
def test_placeholder_secrets_still_start_a_local_stack(monkeypatch, value):
    monkeypatch.setenv("TSI_DPDP_CMS_ENV", "local")
    monkeypatch.setenv("JWT_SECRET", value)
    assert config._secret("JWT_SECRET") == value


def test_real_secret_accepted_outside_local(monkeypatch):
    monkeypatch.setenv("TSI_DPDP_CMS_ENV", "production")
    monkeypatch.setenv("JWT_SECRET", GOOD)
    assert config._secret("JWT_SECRET") == GOOD


# ---- P17-08: the login throttle guards the OTP endpoints -----------------------------------


class FakeThrottle:
    def __init__(self):
        self.locked = set()
        self.failures = []
        self.successes = []

    def require_allowed(self, scope, key):
        if (scope, key) in self.locked:
            raise ApiError(429, "Too Many Requests", "Too many failed attempts. Try again later.")

    def record_failure(self, scope, key, **kw):
        self.failures.append((scope, key, kw.get("max_failures")))

    def record_success(self, scope, key):
        self.successes.append((scope, key))


@pytest.fixture
def otp(otp_store, monkeypatch):  # noqa: F811 (the imported fixture)
    fake = FakeThrottle()
    for name in ("require_allowed", "record_failure", "record_success"):
        monkeypatch.setattr(consent.throttle, name, getattr(fake, name))
    return otp_store, fake


IP = "203.0.113.7"
USER = "asha@example.com"


def _request(user=USER):
    ctx = _ctx("public", "principal", "request_principal_otp", {"fiduciary_id": FID, "user_id": user})
    ctx.source_ip = IP
    return consent.PrincipalService().request_principal_otp(ctx)


def _login(code, user=USER):
    ctx = _ctx("public", "principal", "principal_login", {"fiduciary_id": FID, "user_id": user, "otp": code})
    ctx.source_ip = IP
    return consent.PrincipalService().principal_login(ctx)


def _subject(user=USER):
    return principal_otp.subject_key(FID, user)


def test_wrong_otp_counts_against_principal_and_ip(otp):
    store, fake = otp
    _request()
    wrong = "000000" if store.last_code != "000000" else "111111"
    with pytest.raises(ApiError) as exc:
        _login(wrong)
    assert exc.value.status == 401
    assert fake.failures == [
        (principal_otp.THROTTLE_SUBJECT_SCOPE, _subject(), principal_otp.MAX_SUBJECT_FAILURES),
        (principal_otp.THROTTLE_IP_SCOPE, IP, principal_otp.MAX_IP_FAILURES),
    ]


def test_successful_otp_clears_only_the_principal_bucket(otp):
    store, fake = otp
    _request()
    assert _login(store.last_code)["token"]
    assert fake.successes == [(principal_otp.THROTTLE_SUBJECT_SCOPE, _subject())]


@pytest.mark.parametrize("scope", ["subject", "ip"])
def test_locked_out_login_is_refused_before_the_code_is_checked(otp, scope):
    store, fake = otp
    _request()
    key = _subject() if scope == "subject" else IP
    fake.locked.add((f"otp:{scope}", key))
    with pytest.raises(ApiError) as exc:
        _login(store.last_code)  # even the right code
    assert exc.value.status == 429
    assert store.rows[-1]["consumed_at"] is None  # the code was not burned


@pytest.mark.parametrize("scope", ["subject", "ip"])
def test_locked_out_caller_cannot_request_a_fresh_code(otp, scope):
    store, fake = otp
    key = _subject() if scope == "subject" else IP
    fake.locked.add((f"otp:{scope}", key))
    with pytest.raises(ApiError) as exc:
        _request()
    assert exc.value.status == 429
    assert not store.rows and not store.webhooks


def test_ip_lockout_spans_principals(otp):
    store, fake = otp
    fake.locked.add((principal_otp.THROTTLE_IP_SCOPE, IP))
    with pytest.raises(ApiError) as exc:
        _login("123456", user="someone-else@example.com")
    assert exc.value.status == 429


def test_wrong_dummy_code_is_throttled_too(otp, monkeypatch):
    store, fake = otp
    store.mode = "DUMMY_OTP"
    monkeypatch.setattr(principal_otp, "dummy_allowed", lambda: True)
    with pytest.raises(ApiError):
        _login("9999")
    assert [f[0] for f in fake.failures] == [principal_otp.THROTTLE_SUBJECT_SCOPE, principal_otp.THROTTLE_IP_SCOPE]


# ---- P17-09: a malformed API key is a 401 --------------------------------------------------


@pytest.mark.parametrize("key", ["not-a-uuid", "' OR 1=1 --", "x" * 500, "1234"])
def test_malformed_api_key_is_401(monkeypatch, key):
    queried = []
    monkeypatch.setattr(security.db, "one", lambda *a, **k: queried.append(a) or None)
    response = TestClient(main.app).post(
        "/api/v1/client/consent",
        json={"_func": "get_active_consent", "user_id": "asha"},
        headers={"X-API-Key": key, "X-API-Secret": "s" * 40},
    )
    assert response.status_code == 401, response.text
    assert not queried


def test_well_formed_api_key_still_reaches_the_lookup(monkeypatch):
    queried = []
    monkeypatch.setattr(security.db, "one", lambda sql, params: queried.append(params) or None)
    key = str(uuid.uuid4())
    assert security.api_key_valid(key.upper(), "s" * 40)[0] is False
    assert queried == [(key,)]
