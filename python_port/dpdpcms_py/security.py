from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
import jwt

from . import db
from .config import settings

# The Java port verifies these hashes with jBCrypt 0.4, which accepts only the
# $2$ and $2a$ revisions -- bcrypt's default $2b$ makes it throw "Invalid salt
# revision". Cost 12 matches PasswordHasher.BCRYPT_LOG_ROUNDS on the Java side.
BCRYPT_ROUNDS = 12
BCRYPT_PREFIX = b"2a"


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS, prefix=BCRYPT_PREFIX)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(password: str, stored_hash: str | None) -> bool:
    if not password or not stored_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except Exception:
        return False


def random_secret(size: int = 32) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(size)).decode("ascii").rstrip("=")


def passphrase() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    parts = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(5)]
    return "-".join(parts)


def token(email: str, name: str, role: str, subject: str | None = None, extra: dict[str, Any] | None = None) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": subject or email,
        "email": email,
        "name": name,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.token_ttl_minutes)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_token(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        return jwt.decode(raw, settings.jwt_secret, algorithms=["HS256"])
    except Exception:
        return None


def bearer_token(headers: dict[str, str]) -> str | None:
    auth = headers.get("authorization") or headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def principal_token(fiduciary_id: str, user_id: str) -> str:
    return token(user_id, user_id, "PRINCIPAL", subject=user_id, extra={"fid": fiduciary_id, "typ": "principal"})


def pseudonym(value: str | None) -> str:
    digest = hmac.new(settings.lookup_salt.encode("utf-8"), (value or "").encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:32]


def api_key_valid(api_key: str | None, api_secret: str | None) -> tuple[bool, str | None, set[str]]:
    if not api_key or not api_secret:
        return False, None, set()
    row = db.one(
        "SELECT fiduciary_id, key_value, permissions FROM api_keys WHERE id = %s AND status = 'ACTIVE'",
        (api_key,),
    )
    if not row or not verify_password(api_secret, row.get("key_value")):
        return False, None, set()
    raw = row.get("permissions") or []
    if isinstance(raw, str):
        scopes = {part.strip().upper() for part in raw.strip("[]").replace('"', "").split(",") if part.strip()}
    else:
        scopes = {str(part).strip().upper() for part in raw}
    return True, str(row["fiduciary_id"]), scopes
