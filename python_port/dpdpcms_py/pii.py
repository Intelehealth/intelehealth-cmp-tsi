"""Principal-ID HMAC, encryption and masking primitives.

The principal-ID HMAC trims spaces but keeps case, and the Python side must
equal the SQL `encode(hmac(trim(v), key, 'sha256'), 'hex')` byte for byte. It
is keyed by PII_LOOKUP_KEY, encryption by DB_ENCRYPTION_KEY (P16-04).
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json

from . import db
from .config import settings
from .context import RequestContext

HMAC_SQL = "encode(hmac(trim(%s), %s, 'sha256'), 'hex')"
ENC_SQL = db.enc_expr()


def normalize(value: str | None) -> str | None:
    """Strip spaces only, exactly like Postgres trim() (str.strip() would also drop tabs/newlines)."""
    return None if value is None else value.strip(" ")


def hmac_params(value: str | None) -> tuple[str | None, str]:
    return (normalize(value), settings.pii_lookup_key)


def enc_params(value: str | None) -> tuple[str | None, str]:
    return (normalize(value), settings.db_encryption_key)


def hmac_hex(value: str, key: str | None = None) -> str:
    """The lookup HMAC of a value; `key` only to check one made under an older key."""
    key = key or settings.pii_lookup_key
    return _hmac.new(key.encode(), normalize(value).encode(), hashlib.sha256).hexdigest()


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


def map_principal_keys(value, replace):
    """Copy of a JSON value with replace(key, item) -> (key, item) applied to every PRINCIPAL_KEYS entry."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key in PRINCIPAL_KEYS:
                new_key, new_item = replace(key, item)
                out[new_key] = new_item
            else:
                out[key] = map_principal_keys(item, replace)
        return out
    if isinstance(value, list):
        return [map_principal_keys(item, replace) for item in value]
    return value


def canonical_json(item) -> str:
    return item if isinstance(item, str) else json.dumps(item, sort_keys=True, ensure_ascii=False)


def hmac_principal_keys(value):
    """Copy of a JSON value with every PRINCIPAL_KEYS entry replaced by `<key>_hmac`: hmac_hex(id).

    A non-string value (an object, a list, a number) is hashed whole, as its
    canonical JSON, so nothing under a principal key survives in the clear."""
    return map_principal_keys(
        value, lambda key, item: (f"{key}_hmac", None if item is None else hmac_hex(canonical_json(item)))
    )


def mask_principal_keys(value):
    """Copy of a JSON value with every PRINCIPAL_KEYS entry masked; a non-string value becomes `***`."""
    return map_principal_keys(
        value, lambda key, item: (key, mask(item) if isinstance(item, str) or item is None else "***")
    )


# P16-03: queued alert and webhook payloads hold a principal id under
# PRINCIPAL_KEYS only as `<key>_enc` (ciphertext under DB_ENCRYPTION_KEY) and
# `<key>_hmac` (the lookup HMAC erasure matches on); `<key>_json` marks a
# non-string value, sealed as its canonical JSON. Opened only when read.
SEAL_ENC = "_enc"
SEAL_HMAC = "_hmac"
SEAL_JSON = "_json"


def _crypt_many(sql: str, values: list[str]) -> list[str]:
    """Apply one pgcrypto expression over `v` to many values in a single round trip, in order."""
    if not values:
        return []
    rows = db.all(
        f"SELECT {sql} AS out FROM unnest(%s::text[]) WITH ORDINALITY AS t(v, ord) ORDER BY ord",
        (*db.bind_key(), values),
    )
    return [row["out"] for row in rows]


def seal_principal_keys(value):
    """Copy of a JSON value for storage: every PRINCIPAL_KEYS entry encrypted and HMAC-keyed (P16-03)."""
    plain: list[str] = []

    def collect(key, item):
        if item is not None:
            plain.append(canonical_json(item))
        return key, item

    map_principal_keys(value, collect)
    sealed = iter(_crypt_many("encode(pgp_sym_encrypt(v, %s), 'base64')", plain))

    def walk(node):
        if isinstance(node, dict):
            out = {}
            for key, item in node.items():
                if key not in PRINCIPAL_KEYS:
                    out[key] = walk(item)
                elif item is None:
                    out[key] = None
                else:
                    out[key + SEAL_ENC] = next(sealed)
                    out[key + SEAL_HMAC] = hmac_hex(canonical_json(item))
                    if not isinstance(item, str):
                        out[key + SEAL_JSON] = True
            return out
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return walk(value)


def _sealed_base(key: str) -> str | None:
    if key.endswith(SEAL_ENC) and key[: -len(SEAL_ENC)] in PRINCIPAL_KEYS:
        return key[: -len(SEAL_ENC)]
    return None


def open_principal_keys(values: list):
    """The stored payloads `values` with every sealed principal key decrypted back to its plain key."""
    cipher: list[str] = []

    def collect(node):
        if isinstance(node, dict):
            for key, item in node.items():
                if _sealed_base(key) and isinstance(item, str):
                    cipher.append(item)
                else:
                    collect(item)
        elif isinstance(node, list):
            for item in node:
                collect(item)

    for value in values:
        collect(value)
    opened = iter(_crypt_many("pgp_sym_decrypt(decode(v, 'base64'), %s)", cipher))

    def walk(node):
        if isinstance(node, dict):
            out = {}
            for key, item in node.items():
                base = _sealed_base(key)
                if base and isinstance(item, str):
                    plain = next(opened)
                    out[base] = json.loads(plain) if node.get(base + SEAL_JSON) else plain
                elif key.endswith((SEAL_HMAC, SEAL_JSON)) and isinstance(
                    node.get(key.rsplit("_", 1)[0] + SEAL_ENC), str
                ):
                    continue  # the companions of a sealed key
                else:
                    out[key] = walk(item)
            return out
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return [walk(value) for value in values]


def reseal_matching(value, old_hmac: str, sealed_enc: str, new_hmac: str):
    """Copy of a sealed payload with every principal key whose HMAC is `old_hmac`
    re-sealed as the given (ciphertext, HMAC) pair: erasure's re-key. None when nothing matched."""
    changed = False

    def walk(node):
        nonlocal changed
        if isinstance(node, dict):
            out = {}
            for key, item in node.items():
                base = _sealed_base(key)
                if base and node.get(base + SEAL_HMAC) == old_hmac:
                    changed = True
                    out[key] = sealed_enc
                elif key.endswith(SEAL_HMAC) and item == old_hmac and _sealed_base(key[: -len(SEAL_HMAC)] + SEAL_ENC):
                    out[key] = new_hmac
                elif key.endswith(SEAL_JSON) and node.get(key[: -len(SEAL_JSON)] + SEAL_HMAC) == old_hmac:
                    continue  # the erasure token is a string
                else:
                    out[key] = walk(item)
            return out
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    out = walk(value)
    return out if changed else None


def payload_view(ctx: RequestContext, value):
    """A stored JSON payload as the caller may see it: as stored, or principal keys masked for operators."""
    return value if ctx.operator_id is None else mask_principal_keys(value)


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
