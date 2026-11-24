from __future__ import annotations

import logging
import secrets
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    Service,
    canonical_purpose_id,
    page_limit,
    require,
    tenant_filter,
)
from dpdpcms_py.modules.administration.api import resolve_fiduciary
from dpdpcms_py.modules.audit_logging.ledger import log_event

log = logging.getLogger("dpdpcms.compliance")


# Every status a purge request may carry: the DPO console's PURGE_* / LEGAL_HOLD
# values plus the generic ones from the original schema comment (01_init.sql).
# Mirrored by the CHECK constraint in db/17_defect_fixes.sql.
PURGE_STATUSES = {
    "PENDING",
    "IN_PROGRESS",
    "COMPLETED",
    "FAILED",
    "UNDER_LEGAL_HOLD",
    "PURGE_IN_PROGRESS",
    "PURGE_COMPLETED",
    "PURGE_FAILED",
    "LEGAL_HOLD_APPLIED",
}


PURGE_COMPLETION_STATUSES = {"COMPLETED", "PURGE_COMPLETED"}


def lock_principal_purges(cur, fiduciary_id: str, user_id: str) -> None:
    """Serialise every purge-state change for one principal.

    Taken (transaction-scoped) by _set_purge_status and by the erasure-request
    path that writes LEGAL_HOLD_APPLIED rows, so a hold applied concurrently is
    either visible to the purge's hold check or waits until the purge commits —
    never lands in the gap between the check and the de-identification.
    """
    # Normalise the fiduciary UUID: a payload may send it upper-case while the
    # purge path reads it back lower-case, and both must hash to ONE lock.
    try:
        fiduciary_id = str(uuid.UUID(str(fiduciary_id)))
    except ValueError:
        fiduciary_id = str(fiduciary_id)
    # The principal id is trimmed the way its HMAC is, so the withdrawal path
    # (raw caller input) and the purge path (the decrypted stored id) agree.
    cur.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (f"purge:{fiduciary_id}:{pii.normalize(str(user_id))}",),
    )


@contextmanager
def _cursor(cur=None):
    """Use the caller's cursor (and so its transaction) when given one."""
    if cur is not None:
        yield cur
        return
    with db.connection() as conn, conn.cursor() as own:
        yield own


def erase_cms_copy(
    fiduciary_id: str, user_id: str, action: str = "ERASE", *, cur=None, pending_files: set[str] | None = None
) -> dict[str, int]:
    """SA-13: irreversibly de-identify what the CMS itself holds about a principal.

    The processor deletes the business data; this removes the CMS's own copy of
    the identifier. Every row keyed by the principal is re-keyed to one random
    token per erasure (no key maps it back), so the consent evidence trail stays
    countable but no longer names anyone, and free-text grievance content is
    blanked. SEC-15: the covered set is every table/schema column that stores a
    principal identifier (see ERASURE_TARGETS, kept next to the test that
    enumerates them). The audit log already stores only the pseudonym.

    PL-03: the caller passes `action` — the value stored on the purge request
    (from the retention policy or the closure). ERASE deletes the data_principal
    profile outright; DE_IDENTIFY re-keys it to the pseudonym instead, so the
    two BRD dispositions genuinely behave differently in the CMS rather than
    both boiling down to the same hard delete.

    `cur` runs the erasure inside the caller's transaction (the legal-hold
    race fix in _set_purge_status). Attachment files are then only deleted
    after that transaction commits: the caller passes `pending_files` and
    removes them itself.
    """
    if cur is not None and pending_files is None:
        # Unlinking files inside the caller's uncommitted transaction would test
        # "still referenced?" against rows this transaction has not yet deleted.
        raise ValueError("erase_cms_copy(cur=...) needs pending_files; remove the files after commit.")
    # SA-13: cryptographic erasure. The replacement token is random, not a
    # keyed hash of the identifier, so nobody - not even a holder of the lookup
    # salt - can recompute it from the original id and re-link the evidence
    # rows to the person. The rows stay countable; they no longer name anyone.
    token = f"erased:{secrets.token_hex(16)}"
    counts: dict[str, int] = {}
    # db/34: every predicate below matches the principal's HMAC and every
    # re-key writes the token's encrypted pair (the delivery-floor trigger
    # accepts only an encrypted `erased:` value with its matching HMAC). JSON
    # payloads still carry the raw id the caller supplied, compared trimmed.
    who = pii.hmac_params(user_id)
    raw = pii.normalize(user_id)
    tok = pii.pid_params(token)
    with _cursor(cur) as cur:
        # P5-01: grievance handling runs BEFORE the generic loop below. The
        # generic loop re-keys grievances.user_id to the pseudonym; the DELETE
        # and UPDATE here both predicate on the ORIGINAL user_id, so running
        # them after the loop would match nothing and the evidence would survive
        # erasure. This ordering regressed in the SEC-15 fix; it is fixed here.
        cur.execute(
            f"""
            DELETE FROM grievance_attachments
            WHERE grievance_id IN (SELECT id FROM grievances WHERE fiduciary_id = %s AND {pii.match_sql("user_id")})
            RETURNING storage_path
            """,
            (fiduciary_id, *who),
        )
        attachment_paths = {row["storage_path"] for row in cur.fetchall()}
        counts["grievance_attachments"] = len(attachment_paths)
        # SEC-15: resolution_details is free-text PII written by the DPO;
        # blank it alongside the other grievance text.
        cur.execute(
            f"""
            UPDATE grievances SET {pii.assign_sql("user_id")}, subject = '[erased]', description = '[erased]',
                   resolution_details = NULL,
                   communication_log = '[]'::jsonb, feedback_comment = NULL, attachments = '[]'::jsonb
            WHERE fiduciary_id = %s AND {pii.match_sql("user_id")}
            """,
            (*tok, fiduciary_id, *who),
        )
        counts["grievances"] = cur.rowcount

        # P6-06: statements that match the ORIGINAL user_id must run before the
        # generic loop below, exactly like the grievance block above — the loop
        # re-keys consent_records.user_id and notifications.recipient_id first,
        # which used to make the metadata scrub and the deliveries join match
        # nothing, so the session IP / user agent and the delivery recipient
        # survived erasure.
        db.allow_consent_maintenance(cur)
        # The session IP and any IP the integrator claimed (client_metadata
        # ip_address_enc) are stored encrypted (db/35): each becomes the
        # encrypted 0.0.0.0; a record with no claimed IP keeps none.
        cur.execute(
            f"UPDATE consent_records SET ip_address_enc = {db.enc_expr()}, user_agent = NULL,"
            " client_metadata = CASE WHEN client_metadata ? 'ip_address_enc'"
            f" THEN jsonb_set(client_metadata, '{{ip_address_enc}}', to_jsonb({db.enc_expr()}))"
            " ELSE client_metadata END"
            f" WHERE fiduciary_id = %s AND {pii.match_sql('user_id')}",
            (*db.bind_encrypt("0.0.0.0"), *db.bind_encrypt("0.0.0.0"), fiduciary_id, *who),
        )
        counts["consent_records.metadata"] = cur.rowcount
        cur.execute(
            f"""
            UPDATE notification_deliveries nd SET {pii.assign_sql("recipient")}
            FROM notifications n
            WHERE nd.notification_id = n.id AND n.fiduciary_id = %s
              AND n.recipient_type = 'PRINCIPAL' AND n.{pii.match_sql("recipient_id")}
            """,
            (*tok, fiduciary_id, *who),
        )
        counts["notification_deliveries"] = cur.rowcount
        # GR-11: a resolution notice carries the DPO's free-text summary in its
        # context; it goes with the rest of the grievance text.
        cur.execute(
            "UPDATE notifications SET context = NULL WHERE fiduciary_id = %s AND recipient_type = 'PRINCIPAL'"
            f" AND {pii.match_sql('recipient_id')} AND context IS NOT NULL",
            (fiduciary_id, *who),
        )
        counts["notifications.context"] = cur.rowcount

        for table, column in ERASURE_TARGETS:
            if table == "grievances":
                # P5-01: covered by the dedicated block above, which runs before
                # the generic loop precisely so its WHERE clauses still match the
                # original user_id. Skipped here so the row is not double-keyed.
                continue
            if table == "notification_deliveries":
                # P6-06: handled ahead of the loop for the same reason as the
                # grievances block — the join predicates on the notifications
                # row's ORIGINAL recipient_id.
                continue
            if table == "breach_affected_principals":
                # The table carries no fiduciary_id; its rows hang off
                # breach_incidents, which does.
                cur.execute(
                    f"""
                    UPDATE breach_affected_principals b SET {pii.assign_sql("user_id")}
                    FROM breach_incidents bi
                    WHERE b.breach_id = bi.id AND bi.fiduciary_id = %s AND b.{pii.match_sql("user_id")}
                    """,
                    (*tok, fiduciary_id, *who),
                )
                counts[table] = cur.rowcount
                continue
            if table == "alerts":
                # SEC-15: besides re-keying principal-keyed rows, scrub the raw
                # user_id JSON field the consent-alert payload carries.
                cur.execute(
                    f"UPDATE alerts SET {pii.assign_sql('recipient_id')},"
                    " payload = CASE WHEN payload ? 'user_id'"
                    "             THEN jsonb_set(payload, '{user_id}', to_jsonb(%s::text)) ELSE payload END"
                    f" WHERE fiduciary_id = %s AND recipient_type = 'PRINCIPAL' AND {pii.match_sql('recipient_id')}",
                    (*tok, token, fiduciary_id, *who),
                )
                counts[table] = cur.rowcount
                # P11-06: FIDUCIARY and PROCESSOR alerts about the principal
                # (withdrawal, erasure) carry the raw user_id in their payload
                # too; re-key it whoever the alert is addressed to.
                cur.execute(
                    "UPDATE alerts SET payload = jsonb_set(payload, '{user_id}', to_jsonb(%s::text))"
                    " WHERE fiduciary_id = %s AND recipient_type <> 'PRINCIPAL' AND trim(payload ->> 'user_id') = %s",
                    (token, fiduciary_id, raw),
                )
                counts[table] += cur.rowcount
                # An alert the principal acknowledged names them as the acknowledger.
                cur.execute(
                    f"UPDATE alerts SET {pii.assign_sql('acknowledged_by')}"
                    f" WHERE fiduciary_id = %s AND {pii.match_sql('acknowledged_by')}",
                    (*tok, fiduciary_id, *who),
                )
                counts["alerts.acknowledged_by"] = cur.rowcount
                continue
            cur.execute(
                f"UPDATE {table} SET {pii.assign_sql(column)} WHERE fiduciary_id = %s AND {pii.match_sql(column)}",
                (*tok, fiduciary_id, *who),
            )
            counts[table] = cur.rowcount
        # SEC-15: identifiers that survive the covered set above.
        # evidence_certificates.subject_principal_id stores a principal id.
        cur.execute(
            f"UPDATE evidence_certificates SET {pii.assign_sql('subject_principal_id')}"
            f" WHERE fiduciary_id = %s AND {pii.match_sql('subject_principal_id')}",
            (*tok, fiduciary_id, *who),
        )
        counts["evidence_certificates"] = cur.rowcount
        # data_principal.guardian_id on ANOTHER principal's row: the erased
        # principal is re-keyed so the child's row no longer names the original id.
        cur.execute(
            f"UPDATE data_principal SET {pii.assign_sql('guardian_id')} WHERE fiduciary_id = %s AND {pii.match_sql('guardian_id')}",
            (*tok, fiduciary_id, *who),
        )
        counts["data_principal.guardian_id"] = cur.rowcount
        # webhook_deliveries.payload carries a raw user_id for consent events;
        # re-key it so the queued event no longer names the principal.
        cur.execute(
            "UPDATE webhook_deliveries SET payload = CASE WHEN payload ? 'user_id'"
            "    THEN jsonb_set(payload, '{user_id}', to_jsonb(%s::text)) ELSE payload END"
            " WHERE fiduciary_id = %s AND trim(payload ->> 'user_id') = %s",
            (token, fiduciary_id, raw),
        )
        counts["webhook_deliveries"] = cur.rowcount
        # P16-03: payloads queued since db/37 hold the id sealed (<key>_enc +
        # <key>_hmac), at any depth; re-seal each match as the token.
        old_hmac = pii.hmac_hex(raw)
        sealed_token = None
        for sealed_table in ("alerts", "webhook_deliveries"):
            cur.execute(
                f"SELECT id, payload FROM {sealed_table} WHERE fiduciary_id = %s AND strpos(payload::text, %s) > 0",
                (fiduciary_id, old_hmac),
            )
            for row in cur.fetchall() or []:
                if sealed_token is None:
                    cur.execute(f"SELECT {pii.ENC_SQL} AS enc", pii.enc_params(token))
                    sealed_token = (cur.fetchall()[0]["enc"], pii.hmac_hex(token))
                resealed = pii.reseal_matching(row["payload"], old_hmac, *sealed_token)
                if resealed is not None:
                    cur.execute(
                        f"UPDATE {sealed_table} SET payload = %s WHERE id = %s", (db.as_jsonb(resealed), row["id"])
                    )
                    counts[sealed_table] = counts.get(sealed_table, 0) + 1

        # PL-03: the BRD's two dispositions diverge here. ERASE removes the
        # data_principal profile entirely; DE_IDENTIFY keeps a de-identified
        # copy (the pseudonym) so the fiduciary still has a record of the data
        # subject without the identifier.
        if action == "DE_IDENTIFY":
            cur.execute(
                f"UPDATE data_principal SET {pii.assign_sql('user_id')} WHERE fiduciary_id = %s AND {pii.match_sql('user_id')}",
                (*tok, fiduciary_id, *who),
            )
            counts["data_principal"] = cur.rowcount
        else:
            cur.execute(
                f"DELETE FROM data_principal WHERE fiduciary_id = %s AND {pii.match_sql('user_id')}",
                (fiduciary_id, *who),
            )
            counts["data_principal"] = cur.rowcount
        cur.execute(
            f"UPDATE purge_requests SET cms_erased_at = NOW() WHERE fiduciary_id = %s AND {pii.match_sql('user_id')}",
            (fiduciary_id, *pii.hmac_params(token)),
        )
    if pending_files is not None:
        pending_files.update(attachment_paths)
    else:
        _remove_unreferenced_files(attachment_paths)
    return counts


# SEC-15: every table whose rows carry a principal identifier, mapped to the
# column storing it. extend these in one place; the regression test enumerates
# the schema files against this set so a new table cannot be forgotten.
# `grievances` is listed for coverage but is handled by the dedicated statement
# at the top of erase_cms_copy (P5-01); identifiers reaching the additional
# tables below (evidence_certificates, data_principal.guardian_id,
# consent_records metadata, alerts/webhook payloads) are scrubbed there too.
# Each column is the logical name; db/34 stores it as <column>_enc/<column>_hmac.
ERASURE_TARGETS: tuple[tuple[str, str], ...] = (
    ("consent_records", "user_id"),
    ("notifications", "recipient_id"),
    ("consent_validations", "user_id"),
    ("purge_requests", "user_id"),
    ("grievances", "user_id"),
    ("nominations", "nominating_principal_id"),
    ("nominations", "nominated_principal_id"),
    ("data_correction_requests", "user_id"),
    ("reconsent_requests", "user_id"),
    ("parental_verification_logs", "child_principal_id"),
    ("parental_verification_logs", "guardian_principal_id"),
    ("alerts", "recipient_id"),
    ("notification_deliveries", "recipient"),
    ("breach_affected_principals", "user_id"),
)


def _remove_unreferenced_files(paths: set[str]) -> None:
    """Delete attachment files no remaining row points at.

    Storage is content-addressed, so an identical file uploaded to another
    grievance shares the path and must survive.
    """
    from pathlib import Path

    for path in paths:
        if db.one("SELECT 1 FROM grievance_attachments WHERE storage_path = %s LIMIT 1", (path,)):
            continue
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            log.warning("Could not delete erased attachment file %s", path)


def deidentify_purpose_cms_copy(
    fiduciary_id: str, user_id: str, purpose_id: str, action: str = "ERASE", *, cur=None
) -> dict[str, int]:
    """PL-03: when a PURPOSE closes (not a whole account), the CMS de-identifies
    the consent records held only under it FOR THAT PRINCIPAL.

    The whole-account path (erase_cms_copy) re-keys the principal. A purpose
    closure must not re-key the principal — it must remove that purpose's
    footprint from the CMS's own copy: the `data_point_consents` entries naming
    the purpose are blanked (DE_IDENTIFY) or dropped (ERASE) from the consent
    records of the ONE principal whose purge completed. P7-01: the update MUST
    be scoped by user_id as well as fiduciary_id — scoping by the tenant alone
    made a single processor callback rewrite every consent record in the
    fiduciary that names the purpose, for principals who never had a purge
    raised and whose requests may sit under legal hold.
    """
    from dpdpcms_py.kernel.security import pseudonym

    marker = f"erased:{pseudonym(f'{fiduciary_id}:{purpose_id}')}"
    with _cursor(cur) as cur:
        db.allow_consent_maintenance(cur)
        # DE_IDENTIFY: keep the entry so the consent's history is intact, but
        # blank the fields that name the purpose or the principal's choices.
        # ERASE: drop the entry entirely.
        if action == "DE_IDENTIFY":
            cur.execute(
                f"""
                UPDATE consent_records
                SET data_point_consents = (
                    SELECT jsonb_agg(
                        CASE
                          WHEN lower(btrim(COALESCE(p->>'data_point_id', p->>'purpose_id', p->>'id'))) = %s
                          THEN jsonb_build_object(
                                 'data_point_id', %s::text,
                                 'consent_granted', false,
                                 'status', 'de_identified',
                                 'purpose_agreed_to', '[erased]',
                                 'name', '[erased]'
                               )
                          ELSE p
                        END
                    )
                    FROM jsonb_array_elements(data_point_consents) AS p
                )
                WHERE fiduciary_id = %s AND {pii.match_sql("user_id")}
                  AND EXISTS (SELECT 1 FROM jsonb_array_elements(data_point_consents) q
                              WHERE lower(btrim(COALESCE(q->>'data_point_id', q->>'purpose_id', q->>'id'))) = %s)
                """,
                (
                    canonical_purpose_id(purpose_id),
                    marker,
                    fiduciary_id,
                    *pii.hmac_params(user_id),
                    canonical_purpose_id(purpose_id),
                ),
            )
        else:
            cur.execute(
                f"""
                UPDATE consent_records
                SET data_point_consents = (
                    SELECT COALESCE(jsonb_agg(p), '[]'::jsonb)
                    FROM jsonb_array_elements(data_point_consents) AS p
                    WHERE lower(btrim(COALESCE(p->>'data_point_id', p->>'purpose_id', p->>'id'))) IS DISTINCT FROM %s
                )
                WHERE fiduciary_id = %s AND {pii.match_sql("user_id")}
                  AND EXISTS (SELECT 1 FROM jsonb_array_elements(data_point_consents) q
                              WHERE lower(btrim(COALESCE(q->>'data_point_id', q->>'purpose_id', q->>'id'))) = %s)
                """,
                (
                    canonical_purpose_id(purpose_id),
                    fiduciary_id,
                    *pii.hmac_params(user_id),
                    canonical_purpose_id(purpose_id),
                ),
            )
        return {"consent_records_touched": cur.rowcount}


# A purge request with its principal decrypted; bind *db.bind_key() first.
_PURGE_COLUMNS = f"*, {pii.dec_sql('user_id_enc')} AS user_id"


class ComplianceService(Service):
    def list_purge_requests(self, ctx: RequestContext) -> list[dict]:
        page, limit = page_limit(ctx.payload, 50)
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        where = ["fiduciary_id = %s"]
        params = [fid]
        if ctx.payload.get("status"):
            where.append("status = %s")
            params.append(ctx.payload["status"])
        params.extend([limit, (page - 1) * limit])
        rows = db.all(
            f"SELECT {_PURGE_COLUMNS} FROM purge_requests WHERE {' AND '.join(where)}"
            " ORDER BY initiated_at DESC LIMIT %s OFFSET %s",
            (*db.bind_key(), *params),
        )
        # A PURGE-scope processor needs the identifier to erase the data; the
        # console sees it masked.
        return [pii.principal_row(ctx, row, "user_id") for row in rows]

    def get_purge_request(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        row = db.one(
            f"SELECT {_PURGE_COLUMNS} FROM purge_requests WHERE id = %s{scope}",
            (*db.bind_key(), require(ctx.payload.get("id"), "id"), *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "Purge request not found.")
        return pii.principal_row(ctx, row, "user_id")

    def update_purge_status(self, ctx: RequestContext) -> dict:
        status = str(require(ctx.payload.get("status"), "status")).upper()
        if status not in PURGE_STATUSES:
            raise ApiError(400, "Bad Request", f"status must be one of {sorted(PURGE_STATUSES)}.")
        # INV-07 (SA-09): completion triggers the irreversible CMS erasure, so it
        # is recorded only through confirm_purge_status, with evidence and the
        # caller's identity bound to it - never from a status and a note.
        if status in PURGE_COMPLETION_STATUSES:
            raise ApiError(
                400,
                "Bad Request",
                "A purge is completed only through confirm_purge_status, with evidence of the records erased.",
            )
        return self._set_purge_status(
            ctx, require(ctx.payload.get("id"), "id"), status, ctx.payload.get("details"), evidence=None
        )

    def confirm_purge_status(self, ctx: RequestContext) -> dict:
        """SA-09: the processor that executed a purge confirms it with evidence
        (records affected, who confirmed, any error), so completion is recorded
        as verified rather than assumed.

        SEC-04: the confirmation is bound to the authenticated caller. An API
        key must belong to the app assigned to the purge request, and the
        confirming identity is taken from the credential, never from the free
        `confirmed_by_entity_id` payload text.
        """
        status = str(require(ctx.payload.get("status"), "status")).upper()
        if status not in {"PURGE_COMPLETED", "PURGE_FAILED", "COMPLETED", "FAILED"}:
            raise ApiError(400, "Bad Request", "status must be PURGE_COMPLETED or PURGE_FAILED.")
        try:
            affected = int(require(ctx.payload.get("records_affected_count"), "records_affected_count"))
        except (TypeError, ValueError):
            raise ApiError(400, "Bad Request", "records_affected_count must be an integer.") from None
        if affected < 0:
            raise ApiError(400, "Bad Request", "records_affected_count must not be negative.")
        # SEC-04: the confirming entity is the authenticated credential's owner,
        # not a string the body names. A processor key confirms as its app; a
        # console operator confirms as the signed-in account.
        if ctx.permissions:
            if not ctx.app_id:
                raise ApiError(403, "Forbidden", "This API key is not bound to an app and cannot confirm purges.")
            confirmed_by = ctx.app_id
        elif ctx.operator_id:
            confirmed_by = ctx.actor_email or ctx.operator_id
        else:
            confirmed_by = require(ctx.payload.get("confirmed_by_entity_id"), "confirmed_by_entity_id")
        evidence = {
            "records_affected_count": affected,
            "claimed_records_affected_count": affected,
            "confirmed_by_entity_id": confirmed_by,
            "claimed_confirmed_by_entity_id": ctx.payload.get("confirmed_by_entity_id"),
            "error_message": ctx.payload.get("error_message"),
            "confirmed_at": datetime.now(UTC).isoformat(),
            "confirmed_via": "API_KEY" if ctx.permissions else "CONSOLE",
        }
        return self._set_purge_status(
            ctx,
            require(ctx.payload.get("purge_request_id"), "purge_request_id"),
            "PURGE_COMPLETED" if status in {"PURGE_COMPLETED", "COMPLETED"} else "PURGE_FAILED",
            ctx.payload.get("details"),
            evidence=evidence,
        )

    def _set_purge_status(self, ctx: RequestContext, request_id: str, status: str, details, evidence) -> dict:
        scope, scope_params = tenant_filter(ctx)
        current = db.one(
            f"SELECT id, {pii.dec_sql('user_id_enc')} AS user_id, fiduciary_id, purpose_id, trigger_event, status,"
            f" hold_until, app_id, assigned_operator_id, action FROM purge_requests WHERE id = %s{scope}",
            (*db.bind_key(), request_id, *scope_params),
        )
        if not current:
            raise ApiError(404, "Not Found", "Purge request not found.")
        # SEC-04: an API key may only confirm or update a purge request that is
        # assigned to its own app. A key confirmed_by_entity_id is not checked;
        # the app binding is. Console operators are tenant-scoped above, and a
        # request delegated to a specific operator is that operator's to close.
        if ctx.permissions:
            # P5-04: rows raised by purpose closure, the retention sweep, or a
            # console/principal erasure carry NO app_id; refusing every such row
            # to every key made the processor flow fail-closed. When there is no
            # initiating app the binding falls back to requiring the request is
            # not delegated to a specific operator, so the tenant's processor can
            # close it. An app-initiated row stays bound to that app.
            request_app = str(current.get("app_id") or "") if current.get("app_id") else None
            if request_app:
                if not ctx.app_id or request_app != ctx.app_id:
                    raise ApiError(403, "Forbidden", "This API key is not assigned to the purge request.")
                # SEC-04: the whole-account erasure escalation. A WRITE+PURGE key
                # used to open an erasure on any principal in its tenant, stamp it
                # with its own app_id, then confirm it itself — a single
                # credential reaching irreversible erase_cms_copy. An erasure the
                # key itself opened must be confirmed by a DIFFERENT party: only
                # an operator may complete it.
                if current["trigger_event"] == "ErasureRequest" and current["purpose_id"] == "ALL":
                    raise ApiError(
                        403,
                        "Forbidden",
                        "A whole-account erasure opened by an API key must be confirmed by an operator, not the key that requested it.",
                    )
            elif current.get("assigned_operator_id"):
                raise ApiError(
                    403,
                    "Forbidden",
                    "This purge request is assigned to an operator; it cannot be closed by an API key.",
                )
        elif ctx.operator_id and current.get("assigned_operator_id"):
            # SEC-04: the delegation binds the console too — an operator other
            # than the assignee may not update or confirm the request.
            if str(current["assigned_operator_id"]) != ctx.operator_id:
                raise ApiError(403, "Forbidden", "This purge request is assigned to another operator.")
        completed = status in {"PURGE_COMPLETED", "COMPLETED"}
        fid, user_id = str(current["fiduciary_id"]), str(current["user_id"])
        purpose_scoped = bool(
            completed
            and current["purpose_id"]
            and current["purpose_id"] != "ALL"
            and current["user_id"]
            and current["user_id"] != "ALL"
        )
        whole_account = bool(
            completed and current["trigger_event"] == "ErasureRequest" and current["purpose_id"] == "ALL"
        )
        action = str(current.get("action") or "ERASE").upper()
        erased = None
        pending_files: set[str] = set()
        # Legal-hold race: the hold checks, the status UPDATE and the CMS
        # de-identification run in ONE transaction, serialised per principal
        # with the erasure-request path that writes LEGAL_HOLD_APPLIED rows
        # (lock_principal_purges). A hold applied concurrently is therefore
        # either seen by the checks below or waits until this commits; it can
        # no longer land between the check and the erasure. A refusal raises
        # inside the transaction, so nothing is written (P8-02).
        with db.connection() as conn, conn.cursor() as cur:
            lock_principal_purges(cur, fid, user_id)
            cur.execute(
                "SELECT status, hold_until, app_id, assigned_operator_id FROM purge_requests WHERE id = %s FOR UPDATE",
                (request_id,),
            )
            locked = cur.fetchone() or {}
            # INV-07: a purge that is already complete is not completed again.
            if completed and str(locked.get("status") or "").upper() in PURGE_COMPLETION_STATUSES:
                raise ApiError(409, "Conflict", "This purge request is already completed.")
            # SEC-04: the binding checks above ran on an unlocked read. If the
            # request was reassigned (assign_purge_request) or rebound since,
            # refuse rather than act on authorisation that no longer holds.
            if str(locked.get("app_id") or "") != str(current.get("app_id") or "") or str(
                locked.get("assigned_operator_id") or ""
            ) != str(current.get("assigned_operator_id") or ""):
                raise ApiError(
                    409, "Conflict", "The purge request was reassigned while this update was in flight; retry."
                )
            # CW-11: data under an unexpired legal hold may not be reported
            # deleted. Judged on the locked row, not the earlier unlocked read.
            if (
                completed
                and locked.get("status") == "LEGAL_HOLD_APPLIED"
                and locked.get("hold_until")
                and locked["hold_until"] > datetime.now(UTC)
            ):
                raise ApiError(409, "Conflict", "This request is under a legal hold until its retention period ends.")
            other_hold = None
            if purpose_scoped or whole_account:
                # Any OTHER unexpired hold on this principal (this request's own
                # row is about to change status, and an expired hold on it
                # passed the CW-11 check above).
                cur.execute(
                    f"SELECT 1 FROM purge_requests WHERE fiduciary_id = %s AND {pii.match_sql('user_id')} AND id <> %s"
                    " AND status = 'LEGAL_HOLD_APPLIED' AND (hold_until IS NULL OR hold_until > NOW()) LIMIT 1",
                    (fid, *pii.hmac_params(user_id), request_id),
                )
                other_hold = cur.fetchone()
            if purpose_scoped and other_hold:
                raise ApiError(
                    409,
                    "Conflict",
                    "This principal's data is under a legal hold; the purpose cannot be de-identified yet.",
                )
            cur.execute(
                """
                UPDATE purge_requests SET status = %s, details = COALESCE(%s, details), last_updated_at = NOW(),
                       completion_evidence = COALESCE(%s, completion_evidence),
                       completed_at = CASE WHEN %s THEN NOW() ELSE completed_at END
                WHERE id = %s
                """,
                (status, details, db.as_jsonb(evidence) if evidence else None, completed, request_id),
            )
            # SA-13: once a whole-account erasure is confirmed done (and nothing
            # for this principal is still held by law), the CMS de-identifies its
            # own copy. PL-03: ERASE deletes the profile, DE_IDENTIFY keeps the
            # pseudonym, per the purge request's own `action`.
            if whole_account and not other_hold:
                erased = erase_cms_copy(fid, user_id, action=action, cur=cur, pending_files=pending_files)
            elif purpose_scoped:
                # PL-03: a PURPOSE-scoped purge de-identifies that purpose's
                # footprint for THIS principal only (P7-01).
                erased = deidentify_purpose_cms_copy(fid, user_id, current["purpose_id"], action=action, cur=cur)
        # Files go only after the erasure they belong to has committed.
        _remove_unreferenced_files(pending_files)
        log_event(
            ctx.actor_email or ("INTEGRATOR" if ctx.permissions else "DPO"),
            fid,
            "DPO_CONSOLE" if ctx.category == "admin" else "APP",
            None,
            "PURGE_STATUS_UPDATED",
            {
                "purge_request_id": request_id,
                "status": status,
                "evidence": evidence,
                "cms_copy_erased": bool(erased),
                # A whole-account completion while another hold stands keeps the
                # CMS copy; say so in the trail rather than skipping silently.
                "cms_erasure_deferred_by_legal_hold": bool(whole_account and other_hold),
            },
            purpose_id=current["purpose_id"],
            source_ip=ctx.source_ip,
        )
        # The processor confirming the purge gets the principal it erased; the
        # console sees the identifier masked.
        out = {"success": True, "status": status, "user_id": pii.principal_view(ctx, current["user_id"])}
        if erased is not None:
            out["cms_copy_erased"] = erased
        return out

    def assign_purge_request(self, ctx: RequestContext) -> dict:
        operator_id = require(ctx.payload.get("operator_id"), "operator_id")
        request_id = require(ctx.payload.get("id"), "id")
        # The request and the assignee must both belong to the request's tenant.
        updated = db.execute(
            """
            UPDATE purge_requests pr SET assigned_operator_id = o.id, last_updated_at = NOW()
            FROM operators o
            WHERE pr.id = %s AND o.id = %s AND o.status = 'ACTIVE'
              AND (o.fiduciary_id = pr.fiduciary_id OR o.role = 'ADMIN')
              AND (%s::uuid IS NULL OR pr.fiduciary_id = %s::uuid)
            """,
            (request_id, operator_id, ctx.fiduciary_id, ctx.fiduciary_id),
        )
        if updated == 0:
            raise ApiError(404, "Not Found", "Purge request or operator not found.")
        return {"success": True}
