from __future__ import annotations

from dpdpcms_py.kernel.registry import Module

from .service import RopaService

MODULE = Module(
    name="ropa",
    title="Record of processing activities",
    services={"ropa": RopaService},
    tables=("ropa_entries", "ropa_history"),
)
