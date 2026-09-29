"""RFC 6238 TOTP (time-based one-time passwords) in the stdlib.

Chosen over a third-party dependency so the security-critical primitive is
simple enough to audit and fully deterministic for unit tests. Supports the
temporal drift window used by authenticator apps (30-second nominal step,
default 1 step each way, matching common TOTP clients).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time

DEFAULT_STEP_SECONDS = 30
DIGITS = 6
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def generate_secret(length: int = 32) -> str:
    """A random base32 secret (Google Authenticator style, A-Z2-7, no padding)."""
    bits = secrets.randbits(length * 5)
    out: list[str] = []
    for _ in range(length):
        out.append(ALPHABET[bits & 0x1F])
        bits >>= 5
    return "".join(out)


def _normalise_base32(value: str) -> str:
    return "".join(ch for ch in str(value).upper() if ch in ALPHABET)


def _hotp(secret: str, counter: int) -> str:
    """RFC 4226 HOTP value, 6 digits, given a raw base32 secret."""
    key = base64.b32decode(_normalise_base32(secret) + "=" * ((8 - len(_normalise_base32(secret)) % 8) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 10 ** DIGITS:0{DIGITS}d}"


def totp_at(secret: str, timestamp: float | None = None, step_seconds: int = DEFAULT_STEP_SECONDS) -> str:
    """The TOTP code valid at `timestamp` (defaults to now)."""
    now = timestamp if timestamp is not None else time.time()
    counter = int(now // step_seconds)
    return _hotp(secret, counter)


def verify_totp(
    secret: str,
    code: str,
    timestamp: float | None = None,
    window: int = 1,
    step_seconds: int = DEFAULT_STEP_SECONDS,
) -> bool:
    """True when `code` matches the code valid at `timestamp` within `window` steps."""
    expected = totp_at(secret, timestamp, step_seconds)
    if hmac.compare_digest(expected, _normalise_code(code)):
        return True
    now = timestamp if timestamp is not None else time.time()
    counter = int(now // step_seconds)
    for offset in range(-window, window + 1):
        if offset == 0:
            continue
        candidate = _hotp(secret, counter + offset)
        if hmac.compare_digest(candidate, _normalise_code(code)):
            return True
    return False


def _normalise_code(code: str) -> str:
    return str(code or "").strip()


def otpauth_uri(secret: str, label: str, issuer: str = "TSI DPDP CMS") -> str:
    """Provisioning URI for authenticator apps (otpauth://totp/...)."""
    account = label.replace(":", "")
    params = f"secret={secret}&issuer={issuer.replace(' ', '%20')}&algorithm=SHA1&digits={DIGITS}&period={DEFAULT_STEP_SECONDS}"
    return f"otpauth://totp/{issuer.replace(' ', '%20')}:{account}?{params}"