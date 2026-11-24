from __future__ import annotations

from dpdpcms_py.kernel.registry import Module, Sweep

from . import sweeps
from .service import BreachService

MODULE = Module(
    name="breach",
    title="Personal data breach handling (DPDP Act s.8(6), Rule 7)",
    services={"breach": BreachService},
    sweeps={"breach_deadlines": Sweep(sweeps.flag_breach_board_deadlines, "s.8(6) 72-hour Board intimation clock")},
    tables=("breach_incidents", "breach_affected_principals"),
)
