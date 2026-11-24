"""Cookie Consent: deliberately empty.

DPO decision DD-04 (docs/dpo_decision_register.md): no page under web/ sets a
cookie and the server sends no Set-Cookie header, so CK-01 to CK-10 do not
apply. pentest/test_transport.py checks that this stays true. If an analytics,
embedded-media or third-party tag is ever added, the requirements become live
and their code belongs in this package.
"""

from __future__ import annotations

from dpdpcms_py.kernel.registry import Module

MODULE = Module(
    name="cookie_consent",
    title="Cookie Consent",
    status="not_applicable",
    decision="DD-04",
    requirement_prefixes=("CK",),
)
