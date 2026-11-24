from __future__ import annotations

from dpdpcms_py.kernel.registry import Module, Sweep

from . import sweeps
from .service import JobService

MODULE = Module(
    name="reports",
    title="Queued report and export jobs",
    services={"job": JobService},
    sweeps={"jobs": Sweep(sweeps.execute_queued_jobs, "LG-07 export jobs")},
    tables=("jobs", "job_schedule_state"),
)
