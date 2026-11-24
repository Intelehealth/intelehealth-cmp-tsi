from __future__ import annotations

import json
from typing import Any

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    bind_principal_field,
    canonical_purpose_id,
    ensure_principal_owns,
    page_limit,
    point_purpose_id,
    require,
)
from dpdpcms_py.modules.consent_lifecycle.common import (
    _CONSENT_COLUMNS,
    _USER_MATCH,
    _consent_keys,
    _consent_row,
    _console_record,
    _fid,
    _point_granted,
    _purpose_names,
    _require_console_operator,
)

TRAIL_ALL = "ALL"


def _policy_block(policy_content: Any, language: str) -> dict:
    """The policy's block for `language`, else English, else its first block."""
    if not isinstance(policy_content, dict) or not policy_content:
        return {}
    block = policy_content.get(language) or policy_content.get("en") or next(iter(policy_content.values()))
    return block if isinstance(block, dict) else {}


def _purpose_fields(block: dict) -> dict[str, list[str]]:
    """purpose id -> the names of the data categories it covers, from the policy block.

    Names come from data_categories_details (falling back to the category id);
    they are category labels, never personal data. 'ALL' covers every category
    any purpose names, in declaration order."""
    names = {
        str(c["id"]): str(c.get("name") or c["id"])
        for c in block.get("data_categories_details") or []
        if isinstance(c, dict) and c.get("id")
    }
    out: dict[str, list[str]] = {}
    every: list[str] = []
    for purpose in block.get("data_processing_purposes") or []:
        if not isinstance(purpose, dict) or not purpose.get("id"):
            continue
        fields: list[str] = []
        for category in purpose.get("data_categories_involved") or []:
            name = names.get(str(category), str(category))
            if name not in fields:
                fields.append(name)
            if name not in every:
                every.append(name)
        out[canonical_purpose_id(purpose["id"])] = fields
    out[TRAIL_ALL] = every
    return out


# Context keys by which an audit row names the consent record it is about:
# record_id (CONSENT_GIVEN / CONSENT_WITHDRAWN / ERASURE_REQUESTED) and
# consent_record_id (processor and integrator events).
TRAIL_RECORD_KEYS = ("record_id", "consent_record_id")


def _trail_context(raw: Any) -> Any:
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except ValueError:
        return raw


class RecordHandlers:
    def get_consent_audit_trail(self, ctx: RequestContext) -> dict:
        """Every ledger event about one consent record, grouped by purpose.

        Ported from Consent-Manager (with its f0d65af grouping done here). An
        event belongs to the trail when it is about the record's principal
        (audit user_id = the same pseudonym log_event writes), in the record's
        fiduciary, and names in its context (record_id or consent_record_id)
        this record or one it supersedes, followed back through
        supersedes_record_id. Live and archived years are read. Events group by
        their purpose_id ('ALL' when the row names none); each group lists the
        purpose's name and the data categories it covers in the record's
        policy. The principal id is used only to derive the pseudonym.
        """
        from dpdpcms_py.modules.administration.api import require_audit_access
        from dpdpcms_py.modules.audit_logging.ledger import ledger_source, principal_pseudonym
        from dpdpcms_py.modules.audit_logging.service import _audited_read

        _require_console_operator(ctx)
        # The trail is a read of the audit ledger: gated and audited like one (LG-06, R6-c).
        require_audit_access(ctx)
        record = _console_record(
            ctx,
            f"id, fiduciary_id, policy_id, policy_version, language_selected, {pii.dec_sql('user_id_enc')} AS user_id",
            db.bind_key(),
        )
        fid = str(record["fiduciary_id"])
        if not record.get("user_id"):
            # No principal to derive the ledger pseudonym from: nothing can match.
            _audited_read(ctx, [], "get_consent_audit_trail")
            return {"consent_record_id": str(record["id"]), "purposes": []}
        chain = [
            str(r["id"])
            for r in db.all(
                """
                WITH RECURSIVE chain(id, supersedes_record_id) AS (
                    SELECT id, supersedes_record_id FROM consent_records WHERE id = %s AND fiduciary_id = %s
                    UNION
                    SELECT c.id, c.supersedes_record_id FROM consent_records c
                    JOIN chain ON c.id = chain.supersedes_record_id AND c.fiduciary_id = %s
                )
                SELECT id FROM chain
                """,
                (str(record["id"]), fid, fid),
            )
        ]
        policy = db.one(
            "SELECT policy_content FROM consent_policies WHERE id = %s AND fiduciary_id = %s"
            " ORDER BY (version = %s) DESC, effective_date DESC LIMIT 1",
            (record["policy_id"], fid, record["policy_version"] or ""),
        )
        content = (policy or {}).get("policy_content")
        language = str(record.get("language_selected") or "en")
        names = _purpose_names(content, language)
        fields = _purpose_fields(_policy_block(content, language))
        # Narrowed in SQL by a LIKE on each record id (context_details is not
        # always JSON, so it is never cast there); the exact key match is below.
        rows = db.all(
            f"""
            SELECT id, timestamp, audit_action, service_type, service_id, current_log_hash, prev_log_hash,
                   context_details, purpose_id
            FROM {ledger_source()}
            WHERE user_id = %s AND fiduciary_id = %s AND context_details LIKE ANY(%s)
            ORDER BY timestamp, id
            """,
            (principal_pseudonym(record["user_id"]), fid, [f"%{rid}%" for rid in chain]),
        )
        linked = set(chain)
        groups: dict[str, dict] = {}
        for row in rows:
            context = _trail_context(row["context_details"])
            if not isinstance(context, dict) or not any(
                str(context.get(key)) in linked for key in TRAIL_RECORD_KEYS if context.get(key)
            ):
                continue
            purpose = canonical_purpose_id(row["purpose_id"]) if row.get("purpose_id") else TRAIL_ALL
            group = groups.setdefault(
                purpose,
                {
                    "purpose_id": purpose,
                    "purpose_name": "All purposes" if purpose == TRAIL_ALL else names.get(purpose, purpose),
                    "fields": fields.get(purpose, []),
                    "events": [],
                },
            )
            group["events"].append(
                {
                    "timestamp": row["timestamp"].isoformat() if row.get("timestamp") else None,
                    "audit_action": row["audit_action"],
                    "service_type": row["service_type"],
                    "service_id": None if row["service_id"] is None else str(row["service_id"]),
                    "current_log_hash": row["current_log_hash"],
                    "prev_log_hash": row["prev_log_hash"],
                    # Principal keys hold pseudonyms; rows written before they did are masked.
                    "context": pii.payload_view(ctx, context),
                }
            )
        events = [e for g in groups.values() for e in g["events"]]
        _audited_read(ctx, events, "get_consent_audit_trail")
        return db.to_jsonable({"consent_record_id": str(record["id"]), "purposes": list(groups.values())})

    def get_consent_record_details(self, ctx: RequestContext) -> dict:
        # P4-01: the wallet's GET_CONSENT_DETAILS sends policy_id, not record_id.
        # Accept either: record_id reads one record; policy_id reads the
        # principal's active record for that policy.
        bind_principal_field(ctx, "user_id")
        where: list[str] = []
        params: list[Any] = [*_consent_keys()]
        record_id = ctx.payload.get("record_id")
        policy_id = ctx.payload.get("policy_id")
        if record_id:
            where.append("id = %s")
            params.append(record_id)
        elif policy_id:
            # P6-02: the policy_id branch must name a principal. A principal JWT
            # has user_id bound to the token subject by bind_principal_field /
            # authenticate; an integrator key must send an explicit user_id, so a
            # READ key can no longer read an arbitrary principal's active record
            # without naming one.
            where.append(_USER_MATCH)
            where.append("policy_id = %s")
            where.append("is_active_consent IS TRUE")
            params.extend([*pii.hmac_params(require(ctx.payload.get("user_id"), "user_id")), policy_id])
        else:
            raise ApiError(400, "Bad Request", "'record_id' or 'policy_id' is required.")
        if ctx.fiduciary_id:
            where.append("fiduciary_id = %s")
            params.append(ctx.fiduciary_id)
        row = db.one(
            f"SELECT {_CONSENT_COLUMNS} FROM consent_records WHERE {' AND '.join(where)}"
            " ORDER BY timestamp DESC LIMIT 1",
            params,
        )
        if not row:
            raise ApiError(404, "Not Found", "Consent record not found.")
        ensure_principal_owns(ctx, row.get("user_id"), label="Consent record")
        out = _consent_row(ctx, row)
        # P4-01: give the wallet the policy title and persona labels alongside
        # the record, mirroring what GET_POLICY_PURPOSES returns.
        if out is not None:
            policy = db.one(
                "SELECT policy_content FROM consent_policies WHERE id = %s AND fiduciary_id = %s",
                (row["policy_id"], row["fiduciary_id"]),
            )
            content = (policy or {}).get("policy_content") or {}
            lang_block = next(iter(content.values()), {})
            out["policy_title"] = (lang_block.get("title") if isinstance(lang_block, dict) else None) or str(
                row["policy_id"]
            )
            out["personas"] = db.to_jsonable(
                db.all(
                    """
                    SELECT DISTINCT lower(replace(trim(cat), ' ', '_')) AS id, trim(cat) AS label
                    FROM ropa_entries e,
                         LATERAL jsonb_array_elements_text(
                         CASE WHEN jsonb_typeof(e.data_subject_categories) = 'array'
                              THEN e.data_subject_categories ELSE '[]'::jsonb END) AS cat
                    WHERE e.fiduciary_id = %s AND e.linked_policy_ids @> %s AND e.status = 'active'
                      AND trim(cat) <> ''
                    ORDER BY label LIMIT 100
                    """,
                    (str(row["fiduciary_id"]), db.as_jsonb([str(row["policy_id"])])),
                )
            )
            # UD-02 (DD-01): the dashboard substitutes purpose-lifecycle state and
            # the governing retention period for the expiry date the BRD asked
            # for. Surface both so the principal still sees a temporal fact —
            # just the accurate one for an open-ended consent. P7-06: the
            # retention figure comes from the governing retention policy / ROPA
            # (day count), never from an ISO expiry timestamp, and the lifecycle
            # badge reflects the schema's OPEN/CLOSED values.
            from dpdpcms_py.modules.administration.api import retention_for_purposes

            lifecycle = {
                canonical_purpose_id(r["purpose_id"]): r["state"]
                for r in db.all(
                    "SELECT purpose_id, state FROM purpose_lifecycle WHERE fiduciary_id = %s",
                    (str(row["fiduciary_id"]),),
                )
            }
            points = [
                (point, point_purpose_id(point))
                for point in row.get("data_point_consents") or []
                if isinstance(point, dict)
            ]
            # P8-07: one batched lookup for every purpose, not 1-2 queries each.
            retention = retention_for_purposes(str(row["fiduciary_id"]), [pid for _p, pid in points if pid])
            purposes: list[dict] = []
            for point, pid in points:
                if not pid:
                    continue
                retention_days, _start = retention[pid]
                purposes.append(
                    {
                        "purpose_id": pid,
                        "name": point.get("purpose_agreed_to") or point.get("name"),
                        # P7-06: report the stored lifecycle state (OPEN/CLOSED)
                        # verbatim; default to OPEN only when no lifecycle row
                        # exists. 'ACTIVE' was never a real schema value.
                        "state": lifecycle.get(pid, "OPEN"),
                        "retention_period_days": retention_days,
                    }
                )
            out["purpose_states"] = purposes
        return out

    def list_consents(self, ctx: RequestContext) -> dict:
        """Cross-principal consent listing for the DPO console. Always scoped to one fiduciary."""
        payload = ctx.payload
        page, limit = page_limit(payload, 25)
        where = ["fiduciary_id = %s"]
        params: list[Any] = [_fid(ctx)]
        if payload.get("user_id"):
            # The identifier is stored encrypted: the search matches a whole
            # identifier (spaces trimmed, case kept) through its HMAC.
            where.append(_USER_MATCH)
            params.extend(pii.hmac_params(str(payload["user_id"])))
        if payload.get("policy_id"):
            where.append("policy_id = %s")
            params.append(payload["policy_id"])
        if payload.get("status"):
            where.append("consent_status_general = %s")
            params.append(payload["status"])
        if payload.get("active_only"):
            where.append("is_active_consent IS TRUE")
        if payload.get("start_date"):
            where.append("timestamp >= %s::timestamp")
            params.append(payload["start_date"])
        if payload.get("end_date"):
            where.append("timestamp <= %s::timestamp")
            params.append(payload["end_date"])
        clause = " AND ".join(where)
        total = db.one(f"SELECT COUNT(*) AS count FROM consent_records WHERE {clause}", params)
        rows = db.all(
            f"""
            SELECT id AS record_id, {pii.dec_sql("user_id_enc")} AS user_id, policy_id, policy_version,
                   consent_status_general, is_active_consent, timestamp, language_selected, consent_mechanism,
                   jurisdiction, data_point_consents
            FROM consent_records WHERE {clause}
            ORDER BY timestamp DESC LIMIT %s OFFSET %s
            """,
            [*db.bind_key(), *params, limit, (page - 1) * limit],
        )
        out = []
        for row in db.to_jsonable(rows):
            row["user_id"] = pii.principal_view(ctx, row["user_id"])
            points = row.pop("data_point_consents", None) or []
            points = [p for p in points if isinstance(p, dict)]
            row["purposes_total"] = len(points)
            row["purposes_granted"] = sum(1 for p in points if _point_granted(p))
            out.append(row)
        return {"success": True, "data": out, "page": page, "limit": limit, "total": total["count"] if total else 0}
