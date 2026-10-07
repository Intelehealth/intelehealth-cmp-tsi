"""Generic per-identity attempt throttling (SEC-01 / SEC-03).

Each throttle is keyed by ``(scope, key)`` in the ``auth_throttles`` table so
the same machinery serves the unauthenticated recovery path (keyed by an email
HMAC and by source IP) and operator login (keyed by operator id and by source
IP). A key is refused once `max_failures` consecutive failures are recorded.

P5-02: a lockout expires after `LOCKOUT_MINUTES`, and when a lapsed lock is
next observed the failure counter starts a fresh window instead of re-locking
the key on the very next attempt. The lock itself escalates geometrically
(15m -> 30m -> 1h, capped) so a sustained spray sacrifices access to 60
minutes rather than permalocking everything behind one proxy.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_lib
from datetime import UTC, datetime, timedelta

from . import db
from .config import settings
from .errors import ApiError

MAX_FAILURES = 5
LOCKOUT_MINUTES = 15
# P5-02: backoff doubles each consecutive lock, never above this cap.
MAX_LOCKOUT_MINUTES = 60


def email_key(email: str | None) -> str:
    """A stable, normalised throttle key derived from an email address.

    SEC-01/P5-03: the raw email is never written to auth_throttles.key, and the
    variants 'A@x.y', 'a@x.y' and ' a@x.y ' land in the same bucket. The HMAC
    is computed over lower(trim(email)) with the deployment key, exactly the
    expression the operators.email_hmac lookup uses, so the account buckets and
    the account lookup agree.
    """
    value = (email or "").strip().lower()
    digest = hmac_lib.new(settings.db_encryption_key.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"hmac:{digest}"


def _locked_row(scope: str, key: str) -> dict | None:
    return db.one(
        "SELECT failures, locked_until, lockout_minutes FROM auth_throttles WHERE scope = %s AND key = %s",
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
    """Record one failed attempt; lock the key out once the cap is reached.

    Runs as a read-modify-write inside one transaction so two concurrent
    failures cannot both decide from the same counter value.
    """
    now = datetime.now(UTC)
    with db.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT failures, locked_until, lockout_minutes FROM auth_throttles WHERE scope = %s AND key = %s FOR UPDATE",
            (scope, key),
        )
        row = cur.fetchone()
        if row:
            failures = int(row["failures"] or 0)
            locked_until = row.get("locked_until")
            active_lock = locked_until is not None and locked_until > now
            lapsed_lock = locked_until is not None and locked_until <= now
            previous_minutes = int(row.get("lockout_minutes") or lockout_minutes)
        else:
            failures = 0
            locked_until = None
            active_lock = lapsed_lock = False
            previous_minutes = lockout_minutes
        if active_lock:
            # Still inside the lock: count the attempt but keep the lock.
            new_failures, new_locked, new_minutes = failures + 1, locked_until, previous_minutes
        else:
            # P5-02: a lapsed lock (or a counter already at the cap) starts a
            # fresh window, so one attempt every 15 minutes can no longer keep
            # an account or office locked forever.
            new_failures = 1 if (lapsed_lock or failures >= max_failures) else failures + 1
            if new_failures >= max_failures:
                new_minutes = min(previous_minutes * 2, MAX_LOCKOUT_MINUTES) if previous_minutes else lockout_minutes
                new_locked = now + timedelta(minutes=new_minutes)
            else:
                new_minutes, new_locked = lockout_minutes, None
        cur.execute(
            """
            INSERT INTO auth_throttles (scope, key, failures, locked_until, lockout_minutes, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (scope, key) DO UPDATE SET
                failures = EXCLUDED.failures,
                locked_until = EXCLUDED.locked_until,
                lockout_minutes = EXCLUDED.lockout_minutes,
                updated_at = EXCLUDED.updated_at
            """,
            (scope, key, new_failures, new_locked, new_minutes, now),
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