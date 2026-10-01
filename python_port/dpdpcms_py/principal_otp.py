"""One-time login codes for data principals (rights portal sign-in).

Pure helpers only; the PrincipalService stores and consumes codes. A code is
stored as an HMAC bound to the (fiduciary, principal) subject, so a database
read neither reveals live codes nor lets one subject's code open another's
session.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from .config import settings

TTL_MINUTES = 5
MAX_ATTEMPTS = 5
REQUEST_WINDOW_MINUTES = 15
MAX_REQUESTS_PER_WINDOW = 5
DIGITS = 6

# The rights portal's evaluation mode advertises this fixed code. It is only
# honoured where ALLOW_DUMMY_OTP permits (local environments by default).
DUMMY_CODE = "1234"


def dummy_allowed() -> bool:
    return settings.allow_dummy_otp


def dummy_matches(supplied: str) -> bool:
    return hmac.compare_digest(str(supplied or "").strip(), DUMMY_CODE)


def generate_code() -> str:
    return f"{secrets.randbelow(10**DIGITS):0{DIGITS}d}"


def subject_key(fiduciary_id: str, user_id: str) -> str:
    message = f"{fiduciary_id}:{str(user_id).strip().lower()}".encode()
    return hmac.new(settings.lookup_salt.encode("utf-8"), message, hashlib.sha256).hexdigest()


def code_hash(subject: str, code: str) -> str:
    message = f"{subject}:{str(code).strip()}".encode()
    return hmac.new(settings.jwt_secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def code_matches(subject: str, supplied: str, stored_hash: str | None) -> bool:
    if not stored_hash or not supplied:
        return False
    return hmac.compare_digest(code_hash(subject, supplied), str(stored_hash))
