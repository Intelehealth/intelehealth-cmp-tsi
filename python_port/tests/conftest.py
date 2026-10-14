"""Shared fixtures. `tx` (one rolled-back transaction per test against a live
Postgres) is defined in test_integration_db.py and shared with the files that
build on its seed helpers."""

from tests.test_integration_db import tx  # noqa: F401
