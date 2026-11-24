"""The generated OpenAPI specs (docs/api/) describe what the dispatcher accepts."""

import json

import pytest
from dpdpcms_py import main
from dpdpcms_py import openapi_gen as gen
from dpdpcms_py.config import VALIDATOR_ROOT
from dpdpcms_py.errors import error_body
from dpdpcms_py.services.consent import WALLET_ACTIONS
from dpdpcms_py.services.roles import required_permission
from fastapi import FastAPI


def _op(category, service, func):
    return next(o for o in gen.operations() if (o.category, o.service, o.func) == (category, service, func))


def test_operations_are_sorted_and_unique():
    keys = [(o.category, o.service, o.func) for o in gen.operations()]
    assert keys == sorted(keys) and len(keys) == len(set(keys))


def test_client_operations_match_the_allow_list():
    funcs = {o.func for o in gen.operations() if o.category == "client"}
    assert funcs <= main.CLIENT_ALLOWED_FUNCS
    assert (
        funcs | set(gen.unrouted()["allowed_without_schema"]) >= main.CLIENT_ALLOWED_FUNCS - main.PUBLIC_ALLOWED_FUNCS
    )


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


# ── spec documents ──────────────────────────────────────────────────────────

HTTP = {"get", "post"}


def _refs(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "$ref":
                yield v
            else:
                yield from _refs(v)
    elif isinstance(node, list):
        for v in node:
            yield from _refs(v)


def _keys(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from _keys(v)
    elif isinstance(node, list):
        for v in node:
            yield from _keys(v)


def _type_values(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "type":
                yield v
            yield from _type_values(v)
    elif isinstance(node, list):
        for v in node:
            yield from _type_values(v)


def test_public_spec_has_only_client_and_public_paths():
    paths = gen.build_spec("public")["paths"]
    assert paths and all(p.split("/")[3] in {"client", "public"} for p in paths)
    assert "x-unrouted" not in gen.build_spec("public")


def test_internal_spec_has_one_path_per_operation():
    spec = gen.build_spec("internal")
    assert set(spec["paths"]) == {f"/api/v1/{o.category}/{o.service}/{o.func}" for o in gen.operations()}
    assert spec["openapi"] == "3.0.3" and spec["x-unrouted"] == gen.unrouted()


def test_every_ref_resolves_and_operation_ids_are_unique():
    for audience in ("public", "internal"):
        spec = gen.build_spec(audience)
        for ref in _refs(spec):
            node = spec
            for part in ref.removeprefix("#/").split("/"):
                node = node[part]
        ids = [op["operationId"] for item in spec["paths"].values() for m, op in item.items() if m in HTTP]
        assert len(ids) == len(set(ids))


def test_no_draft07_only_keywords_survive():
    for audience in ("public", "internal"):
        spec = gen.build_spec(audience)
        assert not {"$schema", "if", "then", "else"} & set(_keys(spec["paths"]))
        for item in spec["paths"].values():
            for m, op in item.items():
                if m == "post":
                    schema = op["requestBody"]["content"]["application/json"]["schema"]
                    assert "_func" not in schema.get("required", [])


def test_type_lists_become_nullable():
    assert not any(isinstance(v, list) for v in _type_values(gen.build_spec("internal")))


def test_conditional_rule_is_preserved_not_dropped():
    with_if = [p.stem for p in VALIDATOR_ROOT.glob("*.jschema") if '"if"' in p.read_text(encoding="utf-8")]
    assert with_if
    for func in with_if:
        assert "x-conditional-rule" in json.dumps(gen.request_schema(func))


def test_api_key_requirement_needs_both_headers():
    spec = gen.build_spec("public")
    op = spec["paths"]["/api/v1/client/consent/record_consent"]["post"]
    assert {"apiKey": [], "apiSecret": []} in op["security"] and {"principalBearer": []} in op["security"]
    assert "operatorBearer" not in spec["components"]["securitySchemes"]


def test_public_operations_have_no_security_and_no_401():
    spec = gen.build_spec("public")
    for path, item in spec["paths"].items():
        if path.startswith("/api/v1/public/"):
            assert item["post"]["security"] == [] and "401" not in item["post"]["responses"]


def test_same_function_in_two_categories_is_documented_twice():
    spec = gen.build_spec("internal")
    admin = {o.func for o in gen.operations() if o.category == "admin"}
    func = next(o.func for o in gen.operations() if o.category == "client" and o.func in admin)
    assert len([p for p in spec["paths"] if p.endswith(f"/{func}")]) >= 2


def test_error_schema_matches_error_body():
    schema = gen.build_spec("public")["components"]["schemas"]["Error"]
    assert set(schema["properties"]) == set(error_body(400, "Bad Request", "m", "/p")) == set(schema["required"])


def test_build_is_deterministic():
    first = json.dumps(gen.build_spec("internal"), sort_keys=True)
    assert first == json.dumps(gen.build_spec("internal"), sort_keys=True)


# ── committed files ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("audience", ["public", "internal"])
def test_committed_spec_is_current(audience):
    path = gen.OUTPUT_DIR / gen.OUTPUTS[audience]
    assert path.exists(), "run: python -m dpdpcms_py.openapi_gen"
    assert path.read_text(encoding="utf-8") == gen.render(audience), (
        "API changed; regenerate with: python -m dpdpcms_py.openapi_gen"
    )


def test_write_all_targets_the_given_directory(tmp_path):
    written = gen.write_all(tmp_path)
    assert sorted(p.name for p in written) == sorted(gen.OUTPUTS.values())
    assert (tmp_path / "openapi-public.json").read_text(encoding="utf-8") == gen.render("public")


def test_output_dir_does_not_depend_on_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert gen.OUTPUT_DIR.is_absolute() and gen.OUTPUT_DIR.parts[-2:] == ("docs", "api")


def test_check_mode_reports_a_stale_file(tmp_path, monkeypatch):
    gen.write_all(tmp_path)
    (tmp_path / "openapi-public.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(gen, "OUTPUT_DIR", tmp_path)
    assert gen.main(["--check"]) == 1
    assert (tmp_path / "openapi-public.json").read_text(encoding="utf-8") == "{}\n"


# ── local /docs ─────────────────────────────────────────────────────────────


def test_local_environment_serves_the_internal_spec():
    probe = FastAPI()
    assert main._install_local_openapi(probe, "local") is True
    assert probe.openapi() == gen.build_spec("internal")
    assert probe.openapi() is probe.openapi()


@pytest.mark.parametrize("environment", ["production", "staging", "", "LOCAL "])
def test_other_environments_are_untouched(environment):
    probe = FastAPI()
    original = probe.openapi
    assert main._install_local_openapi(probe, environment) is False
    assert probe.openapi == original
