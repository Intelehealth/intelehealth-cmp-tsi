"""The generated OpenAPI specs (docs/api/) describe what the dispatcher accepts."""

from dpdpcms_py import main
from dpdpcms_py import openapi_gen as gen
from dpdpcms_py.services.consent import WALLET_ACTIONS
from dpdpcms_py.services.roles import required_permission


def _op(category, service, func):
    return next(o for o in gen.operations() if (o.category, o.service, o.func) == (category, service, func))


def test_operations_are_sorted_and_unique():
    keys = [(o.category, o.service, o.func) for o in gen.operations()]
    assert keys == sorted(keys) and len(keys) == len(set(keys))


def test_client_operations_match_the_allow_list():
    funcs = {o.func for o in gen.operations() if o.category == "client"}
    assert funcs <= main.CLIENT_ALLOWED_FUNCS
    assert funcs | set(gen.unrouted()["allowed_without_schema"]) >= main.CLIENT_ALLOWED_FUNCS - main.PUBLIC_ALLOWED_FUNCS


def test_public_and_bootstrap_take_no_operator_auth():
    assert {o.func for o in gen.operations() if o.category == "public"} <= main.PUBLIC_ALLOWED_FUNCS
    assert all(o.security == () for o in gen.operations() if o.category == "public")
    boot = [(o.service, o.func) for o in gen.operations() if o.category == "bootstrap"]
    assert set(boot) == main.BOOTSTRAP_ALLOWED


def test_admin_login_needs_no_auth_and_others_carry_their_permission():
    assert _op("admin", "operator", "login").security == ()
    op = _op("admin", "role", "create_role")
    assert op.security == ("operatorBearer",)
    assert op.permission == required_permission("role", "create_role") == "role:manage"


def test_purge_scope_excludes_principal_tokens():
    op = _op("client", "compliance", "confirm_purge_status")
    assert op.scope == "PURGE" and op.security == ("apiKey",)


def test_get_only_where_the_dispatcher_allows_it():
    for o in gen.operations():
        assert ("get" in o.methods) == main._is_read_classified(o.service, o.func)
    assert _op("client", "consent", "validate_consent").methods == ("post",)


def test_create_prefixes_return_201():
    assert _op("admin", "role", "create_role").success_status == 201
    assert _op("admin", "role", "delete_role").success_status == 200


def test_wallet_is_one_operation_listing_its_actions():
    wallet = [o for o in gen.operations() if o.service == "wallet"]
    assert [(o.category, o.func) for o in wallet] == [("client", "sync")]
    assert all(action in wallet[0].description for action in WALLET_ACTIONS)


def test_no_private_or_base_methods_leak():
    assert not any(o.func.startswith("_") or o.func == "handle" for o in gen.operations())
