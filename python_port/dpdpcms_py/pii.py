"""Principal-ID HMAC, encryption and masking primitives.

The principal-ID HMAC trims spaces but keeps case, and the Python side must
equal the SQL `encode(hmac(trim(v), key, 'sha256'), 'hex')` byte for byte.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac

from . import db
from .config import settings
from .context import RequestContext

HMAC_SQL = "encode(hmac(trim(%s), %s, 'sha256'), 'hex')"
ENC_SQL = db.enc_expr()


def normalize(value: str | None) -> str | None:
    """Strip spaces only, exactly like Postgres trim() (str.strip() would also drop tabs/newlines)."""
    return None if value is None else value.strip(" ")


def hmac_params(value: str | None) -> tuple[str | None, str]:
    return (normalize(value), settings.db_encryption_key)


def enc_params(value: str | None) -> tuple[str | None, str]:
    return (normalize(value), settings.db_encryption_key)


def hmac_hex(value: str) -> str:
    return _hmac.new(settings.db_encryption_key.encode(), normalize(value).encode(), hashlib.sha256).hexdigest()


def dec_sql(column: str) -> str:
    return db.decrypt_col(column)


def _mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    label, dot, tld = domain.rpartition(".")
    if not local or not label or not dot:
        return value[:2] + "***"
    return f"{local[0]}***@{label[0]}***.{tld}"


def _mask_phone(value: str) -> str:
    plus = "+" if value.startswith("+") else ""
    digits = value[len(plus) :]
    if len(digits) <= 4:
        return plus + digits[:2] + "***"
    head = digits[:2]
    return plus + head + "*" * (len(digits) - 4) + digits[-2:]


def mask(value: str | None) -> str | None:
    if not value:
        return value
    if value.startswith("erased:"):
        return "erased"
    if "@" in value:
        return _mask_email(value)
    if value.lstrip("+").isdigit() and len(value.lstrip("+")) >= 7:
        return _mask_phone(value)
    return value[:2] + "***"


def principal_view(ctx: RequestContext, raw: str | None) -> str | None:
    """Plaintext for API-key callers, principal tokens and processors; masked for console operators."""
    return raw if ctx.operator_id is None else mask(raw)


def principal_row(ctx: RequestContext, row: dict, *columns: str) -> dict:
    """Drop each column's _enc/_hmac pair and show its decrypted value as the caller may see it."""
    out = db.to_jsonable(row)
    for column in columns:
        out.pop(f"{column}_enc", None)
        out.pop(f"{column}_hmac", None)
        if column in out:
            out[column] = principal_view(ctx, out[column])
    return out


def recipient_row(ctx: RequestContext, row: dict, *columns: str) -> dict:
    """principal_row for an alert/notification row: its recipient columns name a
    principal only when recipient_type is PRINCIPAL (else an app, fiduciary or
    operator id), so only then are they masked for operators."""
    if str(row.get("recipient_type") or "").upper() == "PRINCIPAL":
        return principal_row(ctx, row, *columns)
    out = db.to_jsonable(row)
    for column in columns:
        out.pop(f"{column}_enc", None)
        out.pop(f"{column}_hmac", None)
    return out


# Keys that carry a principal id inside a JSON document the CMS stores.
PRINCIPAL_KEYS = frozenset(
    {
        "user_id",
        "principal_id",
        "guardian_id",
        "recipient_id",
        "child_principal_id",
        "guardian_principal_id",
        "subject_principal_id",
        "nominating_principal_id",
        "nominated_principal_id",
        "nominee_id",
    }
)


def hmac_principal_keys(value):
    """Copy of a JSON value with every PRINCIPAL_KEYS entry replaced by `<key>_hmac`: hmac_hex(id)."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key in PRINCIPAL_KEYS and isinstance(item, (str, int)) and not isinstance(item, bool):
                out[f"{key}_hmac"] = hmac_hex(str(item))
            else:
                out[key] = hmac_principal_keys(item)
        return out
    if isinstance(value, list):
        return [hmac_principal_keys(item) for item in value]
    return value


# Query fragments for the <col>_enc / <col>_hmac pairs db/34 stores.
PID_VALUES = f"{ENC_SQL}, {HMAC_SQL}"


def match_sql(column: str) -> str:
    """`<column>_hmac = HMAC_SQL`; bind *hmac_params(value)."""
    return f"{column}_hmac = {HMAC_SQL}"


def assign_sql(column: str) -> str:
    """`<column>_enc = ENC_SQL, <column>_hmac = HMAC_SQL`; bind *pid_params(value)."""
    return f"{column}_enc = {ENC_SQL}, {column}_hmac = {HMAC_SQL}"


def pid_params(value: str | None) -> tuple:
    """Parameters for an ENC_SQL, HMAC_SQL pair (PID_VALUES or assign_sql)."""
    return (*enc_params(value), *hmac_params(value))
