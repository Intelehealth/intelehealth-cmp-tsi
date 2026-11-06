"""P16-04: recompute every principal lookup HMAC under the current PII_LOOKUP_KEY.

Lookup HMACs (<col>_hmac) used to be keyed by DB_ENCRYPTION_KEY. Once a
deployment sets a distinct PII_LOOKUP_KEY (or rotates it), every stored HMAC
must be recomputed from the encrypted value beside it, or no lookup matches.
This does it in one transaction: each <col>_hmac with a <col>_enc sibling, and
the sealed principal keys inside alerts and webhook_deliveries payloads.

operators.email_hmac and fiduciaries.email_hmac are not principal lookups (they
are lower-cased, and the sign-in throttle shares their key); they stay keyed by
DB_ENCRYPTION_KEY.

Usage, with the deployment's environment loaded and the worker and API stopped:
    python -m dpdpcms_py.rekey_lookup
"""

from __future__ import annotations

import logging

from psycopg import sql

from . import db, pii
from .config import settings

log = logging.getLogger("dpdpcms.rekey_lookup")

# Not principal lookups: see the module docstring.
EXCLUDED_TABLES = {"operators", "fiduciaries"}


def lookup_columns(cur) -> list[tuple[str, str]]:
    """(table, logical column) for every <col>_hmac that has a <col>_enc beside it."""
    cur.execute(
        """
        SELECT h.table_name, left(h.column_name, length(h.column_name) - 5) AS base
        FROM information_schema.columns h
        JOIN information_schema.columns e
          ON e.table_schema = h.table_schema AND e.table_name = h.table_name
         AND e.column_name = left(h.column_name, length(h.column_name) - 5) || '_enc'
        JOIN information_schema.tables t
          ON t.table_schema = h.table_schema AND t.table_name = h.table_name AND t.table_type = 'BASE TABLE'
        WHERE h.table_schema = 'public' AND h.column_name LIKE '%\\_hmac'
        ORDER BY 1, 2
        """
    )
    return [(row["table_name"], row["base"]) for row in cur.fetchall() if row["table_name"] not in EXCLUDED_TABLES]


def rekey() -> dict[str, int]:
    counts: dict[str, int] = {}
    with db.connection() as conn, conn.cursor() as cur:
        # consent_records is append-only; re-keying its lookup HMAC is one of
        # the sanctioned maintenance rewrites (db/35 trigger).
        db.allow_consent_maintenance(cur)
        for table, base in lookup_columns(cur):
            enc, mac = sql.Identifier(f"{base}_enc"), sql.Identifier(f"{base}_hmac")
            cur.execute(
                sql.SQL(
                    "UPDATE {table} SET {mac} = encode(hmac(trim(pgp_sym_decrypt(decode({enc}, 'base64'), %s)),"
                    " %s, 'sha256'), 'hex') WHERE {enc} IS NOT NULL"
                ).format(table=sql.Identifier(table), mac=mac, enc=enc),
                (settings.db_encryption_key, settings.pii_lookup_key),
            )
            counts[f"{table}.{base}"] = cur.rowcount
        for table in ("alerts", "webhook_deliveries"):
            cur.execute(
                sql.SQL("SELECT id, payload FROM {} WHERE payload::text LIKE %s").format(sql.Identifier(table)),
                ('%\\_hmac"%',),
            )
            rows = cur.fetchall()
            opened = pii.open_principal_keys([row["payload"] for row in rows])
            for row, payload in zip(rows, opened, strict=True):
                cur.execute(
                    sql.SQL("UPDATE {} SET payload = %s WHERE id = %s").format(sql.Identifier(table)),
                    (db.as_jsonb(pii.seal_principal_keys(payload)), row["id"]),
                )
            counts[f"{table}.payload"] = len(rows)
    return counts


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    for name, count in rekey().items():
        log.info("%s: %d row(s) re-keyed", name, count)


if __name__ == "__main__":
    main()
