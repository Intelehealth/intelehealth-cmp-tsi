from __future__ import annotations

from collections.abc import Iterable
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .config import settings


def as_jsonb(value: Any) -> Jsonb:
    return Jsonb(value if value is not None else {})


def enc_expr() -> str:
    return "encode(pgp_sym_encrypt(%s, %s), 'base64')"


def hmac_expr() -> str:
    return "encode(hmac(lower(trim(%s)), %s, 'sha256'), 'hex')"


def decrypt_col(column: str) -> str:
    return f"pgp_sym_decrypt(decode({column}, 'base64'), %s)"


def bind_encrypt(value: str | None) -> tuple[Any, ...]:
    return (value, settings.db_encryption_key)


def bind_hmac(value: str | None) -> tuple[Any, ...]:
    return (value, settings.db_encryption_key)


def bind_key() -> tuple[str]:
    return (settings.db_encryption_key,)


@contextmanager
def connection():
    with psycopg.connect(settings.db_dsn, row_factory=dict_row) as conn:
        if settings.db_encryption_key:
            with conn.cursor() as cur:
                cur.execute("SELECT set_config('app.enc_key', %s, false)", (settings.db_encryption_key,))
        yield conn


def one(sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, tuple(params))
        return cur.fetchone()


def all(sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, tuple(params))
        return list(cur.fetchall())


def execute(sql: str, params: Iterable[Any] = ()) -> int:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, tuple(params))
        return cur.rowcount


def insert_returning(sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, tuple(params))
        return cur.fetchone()


def to_jsonable(row: Any) -> Any:
    if isinstance(row, list):
        return [to_jsonable(item) for item in row]
    if isinstance(row, dict):
        out: dict[str, Any] = {}
        for key, value in row.items():
            if hasattr(value, "isoformat"):
                out[key] = value.isoformat()
            else:
                out[key] = value
        return out
    return row
