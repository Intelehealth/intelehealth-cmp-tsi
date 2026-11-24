"""The code is grouped the way the MeitY/NeGD BRD groups the system.

`dpdpcms_py/modules/` holds one package per BRD module, `extensions/` what the
DPDP Act needs but the BRD does not name, and `kernel/` the plumbing they
share. These tests keep that grouping true: who may import whom, which module
owns each table, and that every module is declared.
"""

from __future__ import annotations

import ast
import re
from collections import Counter
from importlib import import_module
from pathlib import Path

import pytest
from dpdpcms_py import registry

REPO = Path(__file__).resolve().parents[2]
PACKAGE = REPO / "python_port" / "dpdpcms_py"
ENTRY_POINTS = {"main", "worker", "registry", "openapi_gen", "rekey_lookup"}
# Every module writes to the audit ledger, so it is the one module all may import.
SHARED_MODULE = "modules.audit_logging"


def _package_of(dotted: str) -> str:
    parts = dotted.split(".")
    if parts[0] in ("modules", "extensions") and len(parts) > 1:
        return ".".join(parts[:2])
    return parts[0]


def _project_imports(path: Path):
    """(imported dotted path relative to dpdpcms_py, line) for every import in a file."""
    here = path.relative_to(PACKAGE).with_suffix("").parts
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            targets = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = list(here[: len(here) - node.level])
                stem = ".".join(["dpdpcms_py", *base, *(node.module.split(".") if node.module else [])])
            else:
                stem = node.module or ""
            # `from package import name` may name a submodule, so check both spellings.
            targets = [stem] + [f"{stem}.{a.name}" for a in node.names]
        else:
            continue
        for target in targets:
            if target == "dpdpcms_py" or target.startswith("dpdpcms_py."):
                yield target.removeprefix("dpdpcms_py").lstrip("."), node.lineno


def _files(*roots: str):
    for root in roots:
        yield from sorted((PACKAGE / root).rglob("*.py"))


def _exists(dotted: str) -> bool:
    path = PACKAGE / dotted.replace(".", "/")
    return path.with_suffix(".py").exists() or (path / "__init__.py").exists()


def test_kernel_imports_nothing_above_it():
    offenders = [
        f"{path.relative_to(PACKAGE)}:{line} imports {target}"
        for path in _files("kernel")
        for target, line in _project_imports(path)
        if target and _exists(target) and _package_of(target) != "kernel"
    ]
    assert offenders == []


def test_audit_ledger_imports_only_the_kernel():
    """ledger.py is what every module writes through, so it sits directly on the
    kernel. The audit read service beside it checks roles like any other module."""
    path = PACKAGE / "modules" / "audit_logging" / "ledger.py"
    offenders = [
        f"{path.relative_to(PACKAGE)}:{line} imports {target}"
        for target, line in _project_imports(path)
        if target and _exists(target) and _package_of(target) != "kernel"
    ]
    assert offenders == []


def test_modules_reach_each_other_only_through_api():
    """A module may import the kernel, the audit ledger and its own files. Anything
    in another module or extension it takes from that package's api.py."""
    offenders = []
    for path in _files("modules", "extensions"):
        mine = _package_of(".".join(path.relative_to(PACKAGE).with_suffix("").parts))
        for target, line in _project_imports(path):
            if not target or not _exists(target):
                continue
            theirs = _package_of(target)
            if theirs in ("kernel", SHARED_MODULE, mine):
                continue
            if theirs in ENTRY_POINTS:
                offenders.append(f"{path.relative_to(PACKAGE)}:{line} imports the entry point {target}")
            elif theirs in ("modules", "extensions") or target not in (theirs, f"{theirs}.api"):
                offenders.append(f"{path.relative_to(PACKAGE)}:{line} imports {target}, not {theirs}.api")
    assert offenders == []


def _api_modules():
    return [
        ".".join(path.relative_to(PACKAGE.parent).with_suffix("").parts) for path in _files("modules", "extensions")
    ]


@pytest.mark.parametrize("dotted", [m for m in _api_modules() if m.endswith(".api")])
def test_every_api_export_resolves(dotted):
    api = import_module(dotted)
    assert api.__all__, f"{dotted} exports nothing"
    for name in api.__all__:
        assert getattr(api, name) is not None


def test_the_seven_brd_modules_are_declared_in_brd_order():
    assert [m.title for m in registry.BRD_MODULES] == [
        "Consent Management Lifecycle",
        "Cookie Consent",
        "User Dashboard",
        "Consent Notifications",
        "Grievance Redressal Mechanism",
        "System Administration",
        "Logging",
    ]


def test_every_package_with_code_has_a_manifest_in_the_registry():
    declared = {m.name for m in registry.MODULES}
    on_disk = {
        path.name
        for root in ("modules", "extensions")
        for path in (PACKAGE / root).iterdir()
        if path.is_dir() and path.name != "__pycache__"
    }
    assert declared == on_disk
    for name in on_disk:
        root = "modules" if (PACKAGE / "modules" / name).is_dir() else "extensions"
        assert (PACKAGE / root / name / "manifest.py").exists(), f"{root}/{name} has no manifest.py"


def test_a_module_that_is_not_built_cites_a_recorded_dpo_decision():
    register = (REPO / "docs" / "dpo_decision_register.md").read_text(encoding="utf-8")
    for module in registry.MODULES:
        if module.status == "built":
            continue
        assert module.status == "not_applicable"
        assert not module.services and not module.sweeps and not module.tables
        assert module.decision and f"## {module.decision} " in register, module.name


def test_every_table_has_exactly_one_owning_module():
    created = set()
    for script in sorted((REPO / "db").glob("*.sql")):
        for name in re.findall(
            r"CREATE TABLE\s+(?:IF NOT EXISTS\s+)?(?:public\.)?([a-z_0-9]+)", script.read_text(encoding="utf-8")
        ):
            created.add(name)
    # A partition is part of its parent table, not a table of its own.
    # (`public` is the schema of the dynamically named yearly partitions.)
    created -= {"audit_logs_default", "public"}
    owners = Counter(table for module in registry.MODULES for table in module.tables)
    assert [t for t, n in owners.items() if n > 1] == [], "a table is claimed by two modules"
    assert set(owners) == created


def test_every_service_and_sweep_belongs_to_one_module():
    assert set(registry.SERVICE_REGISTRY) == set(registry.SERVICE_ORDER)
    assert list(registry.SWEEPS) == list(registry.SWEEP_ORDER)
    assert set(registry.SERVICE_MODULE) == set(registry.SERVICE_REGISTRY)


def test_no_source_file_is_hidden_by_gitignore():
    """A package named like an ignored runtime folder (`exports/`, `backups/`) is
    silently left out of every commit, and the app then fails to import in CI."""
    import shutil
    import subprocess

    if not shutil.which("git") or not (REPO / ".git").exists():
        pytest.skip("not a git checkout")
    ignored = subprocess.run(
        ["git", "ls-files", "--others", "--ignored", "--exclude-standard", "--", "python_port/dpdpcms_py"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert [p for p in ignored if p.endswith(".py")] == []


def test_no_package_is_left_out_of_the_docker_image():
    patterns = {
        line.strip().strip("/")
        for line in (REPO / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }
    packages = {p.name for p in PACKAGE.rglob("*") if p.is_dir() and p.name != "__pycache__"}
    assert packages & patterns == set()
