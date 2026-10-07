"""Generic per-identity attempt throttling (SEC-01 / SEC-03).

Each throttle is keyed by ``(scope, key)`` in the ``auth_throttles`` table so
the same machinery serves the unauthenticated recovery path (keyed by an email
HMAC and by source IP) and operator login (keyed by operator id and by source
IP). A key is refused once `max_failures` consecutive failures are recorded.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from . import db
from .errors import ApiError

MAX_FAILURES = 5
LOCKOUT_MINUTES = 15


def _locked_row(scope: str, key: str) -> dict | None:
    return db.one(
        "SELECT failures, locked_until FROM auth_throttles WHERE scope = %s AND key = %s",
        (scope, key),
    )


def is_locked(scope: str, key: str) -> bool:
    """True when `key` is currently under a lockout in `scope`."""
    row = _locked_row(scope, key)
    return bool(row and row.get("locked_until") and row["locked_until"] > datetime.now(UTC))


def require_allowed(scope: str, key: str) -> None:
    """Raise 429 if `key` is locked out in `scope`."""
    if is_locked(scope, key):
        raise ApiError(429, "Too Many Requests", "Too many failed attempts. Try again later.")


def record_failure(scope: str, key: str, max_failures: int = MAX_FAILURES, lockout_minutes: int = LOCKOUT_MINUTES) -> None:
    """Record one failed attempt; lock the key out once the cap is reached."""
    db.execute(
        """
        INSERT INTO auth_throttles (scope, key, failures, locked_until, updated_at)
        VALUES (%s, %s, 1, NULL, NOW())
        ON CONFLICT (scope, key) DO UPDATE SET
            failures = auth_throttles.failures + 1,
            locked_until = CASE
                WHEN auth_throttles.locked_until IS NOT NULL AND auth_throttles.locked_until > NOW()
                THEN auth_throttles.locked_until
                WHEN auth_throttles.failures + 1 >= %s THEN NOW() + make_interval(mins => %s)
                ELSE NULL
            END,
            updated_at = NOW()
        """,
        (scope, key, max_failures, lockout_minutes),
    )


def record_success(scope: str, key: str) -> None:
    """Clear a key's failures and lockout after a successful attempt."""
    db.execute("DELETE FROM auth_throttles WHERE scope = %s AND key = %s", (scope, key))


def prune_expired(now: datetime | None = None) -> int:
    """Remove lockout rows whose lock has already lapsed and whose failures
    have aged out; the worker runs this so the table does not grow forever."""
    now = now or datetime.now(UTC)
    # The WHERE uses the same interval the lockout grants; a row with failures
    # but no active lock is also cleared once it stops receiving attempts.
    return db.execute("DELETE FROM auth_throttles WHERE updated_at < %s", (now - timedelta(hours=24),)) or 0