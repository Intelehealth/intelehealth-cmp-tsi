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


OPERATOR_TOKEN_TYPE = "operator"
# P17-02: operator tokens issued before typ=operator existed carry no typ. They
# are honoured only when issued before this process started (they expire within
# token_ttl_minutes); an untyped token minted after start-up is refused.
UNTYPED_TOKEN_CUTOFF = int(datetime.now(UTC).timestamp())


def is_operator_token(claims: dict[str, Any]) -> bool:
    """True when decoded `claims` are an operator session token."""
    if not claims.get("email"):
        return False
    typ = claims.get("typ")
    if typ is None:
        return int(claims.get("iat") or 0) < UNTYPED_TOKEN_CUTOFF
    return typ == OPERATOR_TOKEN_TYPE


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
        # P17-02: every token says what it is. The admin API accepts only
        # typ=operator; principal_token overrides this with typ=principal.
        "typ": OPERATOR_TOKEN_TYPE,
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


def api_key_valid(api_key: str | None, api_secret: str | None) -> tuple[bool, str | None, set[str], str | None]:
    if not api_key or not api_secret:
        return False, None, set(), None
    # P17-09: key ids are UUIDs. A malformed one is a failed authentication
    # (401), not a value Postgres rejects with a DataError.
    try:
        api_key = str(uuid.UUID(str(api_key).strip()))
    except ValueError:
        return False, None, set(), None
    # INV-08 (SA-05): a key authenticates only while its fiduciary, and the app
    # it is bound to, are still ACTIVE - deactivating either stops its keys.
    row = db.one(
        "SELECT k.fiduciary_id, k.app_id, k.key_value, k.permissions FROM api_keys k"
        " JOIN fiduciaries f ON f.id = k.fiduciary_id AND f.status = 'ACTIVE'"
        " LEFT JOIN apps a ON a.id = k.app_id"
        " WHERE k.id = %s AND k.status = 'ACTIVE' AND (k.expires_at IS NULL OR k.expires_at > NOW())"
        " AND (k.app_id IS NULL OR a.status = 'ACTIVE')",
        (api_key,),
    )
    if not row or not verify_password(api_secret, row.get("key_value")):
        return False, None, set(), None
    raw = row.get("permissions") or []
    if isinstance(raw, str):
        scopes = {part.strip().upper() for part in raw.strip("[]").replace('"', "").split(",") if part.strip()}
    else:
        scopes = {str(part).strip().upper() for part in raw}
    app_id = str(row["app_id"]) if row.get("app_id") else None
    return True, str(row["fiduciary_id"]), scopes, app_id
