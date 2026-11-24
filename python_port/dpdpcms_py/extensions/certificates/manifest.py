from __future__ import annotations

from dpdpcms_py.kernel.registry import Module

from .service import LegalService

MODULE = Module(
    name="certificates",
    title="Evidence certificates",
    services={"legal": LegalService},
    tables=("evidence_certificates",),
)
