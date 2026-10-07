"""Regression tests for the defects raised in MeitY_BRD_API_Traceability_v4.xlsx
("Defect Remediation" sheet): #7/D12 SSRF allow-list, D11 role classifier,
D13 README upgrade path, D14 wallet scope bypass, D15 grievance attachments.

No database: the db helpers are monkeypatched.
"""

import ast
import base64
import re
from contextlib import contextmanager
from pathlib import Path

import pytest
from dpdpcms_py import main, netutil
from dpdpcms_py.context import RequestContext
from dpdpcms_py.errors import ApiError
from dpdpcms_py.services import compliance, consent, roles

FID = "11111111-1111-1111-1111-111111111111"
REPO = Path(__file__).resolve().parents[2]
SERVICES = Path(__file__).resolve().parents[1] / "dpdpcms_py" / "services"


def _ctx(category="client", service="consent", func="list_consents", payload=None, **kwargs):
    return RequestContext(
        path=f"/api/v1/{category}/{service}",
        category=category,
        service=service,
        payload={"_func": func, **(payload or {})},
        headers=kwargs.pop("headers", {}),
        **kwargs,
    )


# ── #7 / D12 SSRF allow-list covers IPv6 forms that reach IPv4 ──────────────
@pytest.mark.parametrize(
    "address",
    [
        "::ffff:169.254.169.254",  # IPv4-mapped metadata endpoint
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::",
        "::127.0.0.1",  # IPv4-compatible
        "64:ff9b::a9fe:a9fe",  # NAT64 of 169.254.169.254
        "64:ff9b:1::1",
        "2002:a9fe:a9fe::1",  # 6to4 of 169.254.169.254
        "2001:db8::1",
        "fe80::1%eth0",
        "0.0.0.0",
    ],
)
def test_ssrf_refuses_tunnelled_and_reserved_addresses(address):
    assert netutil._is_private(address)
    with pytest.raises(ValueError):
        netutil.resolve_public(address)


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_ssrf_allows_public_addresses(address):
    assert not netutil._is_private(address)


def test_ssrf_refuses_hostname_resolving_to_mapped_address(monkeypatch):
    infos = [(None, None, None, None, ("::ffff:169.254.169.254", 0, 0, 0))]
    monkeypatch.setattr(netutil.socket, "getaddrinfo", lambda *a, **k: infos)
    with pytest.raises(ValueError):
        netutil.resolve_public("rebind.example.com")


# ── D11 the role gate classifies by an explicit rule, not a validate_ prefix ─
def test_validate_functions_that_write_need_write_permission():
    assert roles.required_permission("fiduciary", "validate_fiduciary_domain") == "fiduciary:write"
    assert roles.required_permission("consent", "validate_consent") == "consent:write"
    # Side-effect-free validators stay readable by AUDITOR.
    assert roles.required_permission("ropa", "validate_completeness") == "ropa:read"
    assert roles.required_permission("retention", "validate_completeness") == "retention:read"


_WRITE_SQL = re.compile(r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b", re.IGNORECASE)


def test_no_read_classified_function_writes():
    """Every service method the gate treats as a read must contain no SQL write."""
    offenders = []
    for path in SERVICES.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.ClassDef):
                continue
            for fn in node.body:
                if not isinstance(fn, ast.FunctionDef) or fn.name.startswith("_"):
                    continue
                read = fn.name.startswith(roles.READ_PREFIXES) or any(
                    func == fn.name and perm.endswith(":read") for (_, func), perm in roles.FUNC_PERMISSIONS.items()
                )
                if read and _WRITE_SQL.search(ast.get_source_segment(source, fn) or ""):
                    offenders.append(f"{path.name}:{node.name}.{fn.name}")
    assert offenders == []


# ── D13 README upgrade loop applies every migration ─────────────────────────
def test_readme_upgrade_loop_lists_every_migration():
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    loop = next(part for part in readme.split("```bash")[1:] if "for f in db/" in part).split("```", 1)[0]
    assert "\\n" not in loop, "literal \\n breaks the shell continuation"
    listed = set(re.findall(r"db/(\d{2})_[\w.]+\.sql", loop))
    on_disk = {p.name[:2] for p in (REPO / "db").glob("*.sql") if int(p.name[:2]) >= 13}
    assert on_disk <= listed
    assert "migrations `13`–`16`" not in readme


# ── D14 wallet actions are authorised as the function they run ──────────────
@pytest.mark.parametrize(
    "action,target",
    [
        ("GRANT_CONSENT", "record_consent"),
        ("GLOBAL_ERASURE", "erasure_request"),
        ("REVOKE_PURPOSE", "erasure_request"),
        ("GET_CONSENT_DETAILS", "get_consent_record_details"),
        ("GET_POLICY_PURPOSES", "get_active_policy"),
    ],
)
def test_wallet_action_resolves_to_real_function(action, target):
    payload = {"_func": "sync", "action": action.lower()}
    consent.resolve_wallet_action(payload)
    assert payload["_func"] == target


def test_wallet_unknown_action_rejected():
    with pytest.raises(ApiError) as exc:
        consent.resolve_wallet_action({"_func": "sync", "action": "DROP_EVERYTHING"})
    assert exc.value.status == 400


@pytest.mark.parametrize("action", ["GRANT_CONSENT", "GLOBAL_ERASURE"])
def test_read_scoped_key_cannot_write_through_wallet(monkeypatch, action):
    monkeypatch.setattr(main, "api_key_valid", lambda *a: (True, FID, {"READ"}, None))
    payload = {"_func": "sync", "action": action}
    consent.resolve_wallet_action(payload)
    ctx = _ctx(service="wallet", func=payload.pop("_func"), payload=payload)
    with pytest.raises(ApiError) as exc:
        main.authenticate(ctx)
    assert exc.value.status == 401


def test_read_scoped_key_can_still_read_through_wallet(monkeypatch):
    monkeypatch.setattr(main, "api_key_valid", lambda *a: (True, FID, {"READ"}, None))
    payload = {"_func": "sync", "action": "GET_CONSENT_DETAILS"}
    consent.resolve_wallet_action(payload)
    ctx = _ctx(service="wallet", func=payload.pop("_func"), payload=payload)
    main.authenticate(ctx)
    assert ctx.fiduciary_id == FID


def test_wallet_handle_runs_resolved_function(monkeypatch):
    called = []
    monkeypatch.setattr(consent.ConsentService, "record_consent", lambda self, ctx: called.append(ctx.func) or "ok")
    ctx = _ctx(service="wallet", func="record_consent")
    assert consent.WalletService().handle(ctx) == "ok"
    assert called == ["record_consent"]


# ── D15 grievance attachments can be read back and are erased ───────────────
def test_attachment_retrieval_scoped_to_principal(monkeypatch, tmp_path):
    stored = tmp_path / "abc"
    stored.write_bytes(b"evidence")
    seen = {}

    def fake_one(sql, params=()):
        seen["sql"], seen["params"] = sql, params
        return {
            "id": "att-1",
            "grievance_id": "g-1",
            "file_name": "x.txt",
            "content_type": "text/plain",
            "size_bytes": 8,
            "sha256": "abc",
            "storage_path": str(stored),
            "uploaded_by": "asha",
            "created_at": None,
        }

    monkeypatch.setattr(compliance.db, "one", fake_one)
    ctx = _ctx(
        service="grievance",
        func="get_grievance_attachment",
        payload={"attachment_id": "att-1"},
        fiduciary_id=FID,
        principal_user_id="asha",
        auth_via_principal_jwt=True,
    )
    out = compliance.GrievanceService().get_grievance_attachment(ctx)
    assert base64.b64decode(out["content_base64"]) == b"evidence"
    assert "storage_path" not in out
    assert "a.fiduciary_id = %s" in seen["sql"] and "g.user_id = %s" in seen["sql"]
    assert seen["params"] == ("att-1", FID, "asha")


def test_attachment_retrieval_not_found(monkeypatch):
    monkeypatch.setattr(compliance.db, "one", lambda *a, **k: None)
    ctx = _ctx(service="grievance", func="get_grievance_attachment", payload={"attachment_id": "x"}, fiduciary_id=FID)
    with pytest.raises(ApiError) as exc:
        compliance.GrievanceService().get_grievance_attachment(ctx)
    assert exc.value.status == 404


def test_attachment_retrieval_is_client_readable():
    assert "get_grievance_attachment" in main.CLIENT_ALLOWED_FUNCS
    assert main.CLIENT_FUNC_SCOPES["get_grievance_attachment"] == "READ"
    assert roles.required_permission("grievance", "get_grievance_attachment") == "grievance:read"


class _Cursor:
    def __init__(self, paths):
        self.paths = paths
        self.sql = []
        self.rowcount = 1
        self._rows = []

    def execute(self, sql, params=()):
        self.sql.append(sql)
        self._rows = [{"storage_path": p} for p in self.paths] if "RETURNING storage_path" in sql else []

    def fetchall(self):
        return self._rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_erasure_deletes_attachments_but_keeps_shared_files(monkeypatch, tmp_path):
    mine, shared = tmp_path / "mine", tmp_path / "shared"
    mine.write_bytes(b"1")
    shared.write_bytes(b"2")
    cursor = _Cursor([str(mine), str(shared)])

    class _Conn:
        def cursor(self):
            return cursor

    @contextmanager
    def fake_connection():
        yield _Conn()

    monkeypatch.setattr(compliance.db, "connection", fake_connection)
    # The shared file is still referenced by another principal's grievance.
    monkeypatch.setattr(compliance.db, "one", lambda sql, params=(): {"x": 1} if params[0] == str(shared) else None)
    counts = compliance.erase_cms_copy(FID, "asha")
    assert counts["grievance_attachments"] == 2
    assert any("DELETE FROM grievance_attachments" in s for s in cursor.sql)
    assert any("attachments = '[]'::jsonb" in s for s in cursor.sql)
    assert not mine.exists()
    assert shared.exists()
