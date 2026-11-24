"""What a module declares about itself.

A package under `modules/` or `extensions/` is a module because it has a
`manifest.py` exporting one `Module`. `dpdpcms_py.registry` assembles the
service registry and the worker's sweep table from those manifests; nothing
here imports a module.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Sweep:
    """One background task the worker runs every cycle."""

    func: Callable[[], Any]
    note: str


@dataclass(frozen=True)
class Module:
    name: str
    # The module's title in the MeitY/NeGD BRD, or what an extension is for.
    title: str
    # BRD sub-module titles this package implements.
    submodules: tuple[str, ...] = ()
    # "built" or "not_applicable"; the latter cites a DPO decision.
    status: str = "built"
    decision: str | None = None
    # Prefixes of the traceability workbook's requirement ids (CC-01, GR-07...).
    requirement_prefixes: tuple[str, ...] = ()
    # URL service name -> service class. The name is part of the public API.
    services: dict[str, type] = field(default_factory=dict)
    # Sweep name (as the worker heartbeat reports it) -> Sweep.
    sweeps: dict[str, Sweep] = field(default_factory=dict)
    # Tables this module owns. Every table has exactly one owner.
    tables: tuple[str, ...] = ()
    notes: str = ""
