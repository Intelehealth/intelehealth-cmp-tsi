from __future__ import annotations

import dataclasses
import logging
import secrets
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime

from .. import db
from ..audit import log_event
from ..context import RequestContext
from ..errors import ApiError
from .admin import authenticated_user_id
from .base import (
    Service,
    bind_principal_field,
    canonical_purpose_id,
    ensure_principal_owns,
    page_limit,
    require,
    tenant_filter,
)
from .catalog import resolve_fiduciary

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


# GR-02: the complaint categories the rights portal offers, plus the two
# consent-specific ones the BRD names (consent and data handling).
GRIEVANCE_TYPES = {
    "GENERAL_COMPLAINT",
    "ERASURE_REQUEST",
    "DATA_ACCESS_REQUEST",
    "CORRECTION_REQUEST",
    "CONSENT_COMPLAINT",
    "DATA_HANDLING_COMPLAINT",
}
GRIEVANCE_STATUSES = {"NEW", "IN_PROGRESS", "ESCALATED", "RESOLVED", "CLOSED"}
ATTACHMENT_TYPES = {"application/pdf", "image/png", "image/jpeg", "text/plain"}
# GR-10: the notification a principal receives at each grievance stage.
GRIEVANCE_STAGE_NOTICES = {
    "ASSIGNED": "GRIEVANCE_ASSIGNED",
    "IN_PROGRESS": "GRIEVANCE_IN_PROGRESS",
    "ESCALATED": "GRIEVANCE_ESCALATED",
    "RESOLVED": "GRIEVANCE_RESOLVED",
    "CLOSED": "GRIEVANCE_RESOLVED",
}


def _notify_grievance_stage(
    user_id: str, fiduciary_id: str, stage: str, context: dict | None = None, language: str | None = None
) -> None:
    notice = GRIEVANCE_STAGE_NOTICES.get(stage)
    # GR-03: the principal is answered in the language they filed in, not the
    # language of their last consent; delivery reads context.language first.
    if language:
        context = {**(context or {}), "language": language}
    if notice:
        db.execute(
            "INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type, context)"
            " VALUES ('PRINCIPAL', %s, %s, %s, %s)",
            (user_id, fiduciary_id, notice, db.as_jsonb(context) if context else None),
        )


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
    cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"purge:{fiduciary_id}:{str(user_id)}",))


def officer_can_handle_grievances(role: str | None, fiduciary_id: str | None) -> bool:
    """GR-07: an officer a grievance is routed or assigned to must hold
    grievance:write, or the complaint lands with someone who cannot act on it."""
    from .roles import has_permission, role_permissions

    officer_ctx = RequestContext(
        path="",
        category="admin",
        service="grievance",
        payload={},
        headers={},
        auth_token={"role": role},
        fiduciary_id=fiduciary_id,
    )
    return has_permission(role_permissions(officer_ctx), "grievance:write")


@contextmanager
def _cursor(cur=None):
    """Use the caller's cursor (and so its transaction) when given one."""
    if cur is not None:
        yield cur
        return
    with db.connection() as conn, conn.cursor() as own:
        yield own


def _notify_grievance_assignee(
    operator_id: str, fiduciary_id: str, grievance_id: str, reference_number: str | None, grievance_type: str | None
) -> None:
    """P7-05: the officer a grievance is routed to gets their OWN notice (not the
    principal's copy) naming the grievance, so they know which complaint to act on."""
    db.execute(
        "INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type, context)"
        " VALUES ('DPO', %s, %s, 'GRIEVANCE_ROUTED', %s)",
        (
            operator_id,
            fiduciary_id,
            db.as_jsonb(
                {
                    "grievance_id": grievance_id,
                    "reference_number": reference_number or grievance_id,
                    "grievance_type": grievance_type or "",
                }
            ),
        ),
    )


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
    with _cursor(cur) as cur:
        # P5-01: grievance handling runs BEFORE the generic loop below. The
        # generic loop re-keys grievances.user_id to the pseudonym; the DELETE
        # and UPDATE here both predicate on the ORIGINAL user_id, so running
        # them after the loop would match nothing and the evidence would survive
        # erasure. This ordering regressed in the SEC-15 fix; it is fixed here.
        cur.execute(
            """
            DELETE FROM grievance_attachments
            WHERE grievance_id IN (SELECT id FROM grievances WHERE fiduciary_id = %s AND user_id = %s)
            RETURNING storage_path
            """,
            (fiduciary_id, user_id),
        )
        attachment_paths = {row["storage_path"] for row in cur.fetchall()}
        counts["grievance_attachments"] = len(attachment_paths)
        # SEC-15: resolution_details is free-text PII written by the DPO;
        # blank it alongside the other grievance text.
        cur.execute(
            """
            UPDATE grievances SET user_id = %s, subject = '[erased]', description = '[erased]',
                   resolution_details = NULL,
                   communication_log = '[]'::jsonb, feedback_comment = NULL, attachments = '[]'::jsonb
            WHERE fiduciary_id = %s AND user_id = %s
            """,
            (token, fiduciary_id, user_id),
        )
        counts["grievances"] = cur.rowcount

        # P6-06: statements that match the ORIGINAL user_id must run before the
        # generic loop below, exactly like the grievance block above — the loop
        # re-keys consent_records.user_id and notifications.recipient_id first,
        # which used to make the metadata scrub and the deliveries join match
        # nothing, so the session IP / user agent and the delivery recipient
        # survived erasure.
        db.allow_consent_maintenance(cur)
        cur.execute(
            "UPDATE consent_records SET ip_address = '0.0.0.0', user_agent = NULL"
            " WHERE fiduciary_id = %s AND user_id = %s",
            (fiduciary_id, user_id),
        )
        counts["consent_records.metadata"] = cur.rowcount
        cur.execute(
            """
            UPDATE notification_deliveries nd SET recipient = %s
            FROM notifications n
            WHERE nd.notification_id = n.id AND n.fiduciary_id = %s
              AND n.recipient_type = 'PRINCIPAL' AND n.recipient_id = %s
            """,
            (token, fiduciary_id, user_id),
        )
        counts["notification_deliveries"] = cur.rowcount
        # GR-11: a resolution notice carries the DPO's free-text summary in its
        # context; it goes with the rest of the grievance text.
        cur.execute(
            "UPDATE notifications SET context = NULL"
            " WHERE fiduciary_id = %s AND recipient_type = 'PRINCIPAL' AND recipient_id = %s AND context IS NOT NULL",
            (fiduciary_id, user_id),
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
                    """
                    UPDATE breach_affected_principals b SET user_id = %s
                    FROM breach_incidents bi
                    WHERE b.breach_id = bi.id AND bi.fiduciary_id = %s AND b.user_id = %s
                    """,
                    (token, fiduciary_id, user_id),
                )
                counts[table] = cur.rowcount
                continue
            if table == "alerts":
                # SEC-15: besides re-keying principal-keyed rows, scrub the raw
                # user_id JSON field the consent-alert payload carries.
                cur.execute(
                    "UPDATE alerts SET recipient_id = %s,"
                    " payload = CASE WHEN payload ? 'user_id'"
                    "             THEN jsonb_set(payload, '{user_id}', to_jsonb(%s::text)) ELSE payload END"
                    " WHERE fiduciary_id = %s AND recipient_type = 'PRINCIPAL' AND recipient_id = %s",
                    (token, token, fiduciary_id, user_id),
                )
                counts[table] = cur.rowcount
                # P11-06: FIDUCIARY and PROCESSOR alerts about the principal
                # (withdrawal, erasure) carry the raw user_id in their payload
                # too; re-key it whoever the alert is addressed to.
                cur.execute(
                    "UPDATE alerts SET payload = jsonb_set(payload, '{user_id}', to_jsonb(%s::text))"
                    " WHERE fiduciary_id = %s AND recipient_type <> 'PRINCIPAL' AND payload ->> 'user_id' = %s",
                    (token, fiduciary_id, user_id),
                )
                counts[table] += cur.rowcount
                continue
            cur.execute(
                f"UPDATE {table} SET {column} = %s WHERE fiduciary_id = %s AND {column} = %s",
                (token, fiduciary_id, user_id),
            )
            counts[table] = cur.rowcount
        # SEC-15: identifiers that survive the covered set above.
        # evidence_certificates.subject_principal_id stores a principal id.
        cur.execute(
            "UPDATE evidence_certificates SET subject_principal_id = %s WHERE fiduciary_id = %s AND subject_principal_id = %s",
            (token, fiduciary_id, user_id),
        )
        counts["evidence_certificates"] = cur.rowcount
        # data_principal.guardian_id on ANOTHER principal's row: the erased
        # principal is re-keyed so the child's row no longer names the original id.
        cur.execute(
            "UPDATE data_principal SET guardian_id = %s WHERE fiduciary_id = %s AND guardian_id = %s",
            (token, fiduciary_id, user_id),
        )
        counts["data_principal.guardian_id"] = cur.rowcount
        # webhook_deliveries.payload carries a raw user_id for consent events;
        # re-key it so the queued event no longer names the principal.
        cur.execute(
            "UPDATE webhook_deliveries SET payload = CASE WHEN payload ? 'user_id'"
            "    THEN jsonb_set(payload, '{user_id}', to_jsonb(%s::text)) ELSE payload END"
            " WHERE fiduciary_id = %s AND payload ->> 'user_id' = %s",
            (token, fiduciary_id, user_id),
        )
        counts["webhook_deliveries"] = cur.rowcount

        # PL-03: the BRD's two dispositions diverge here. ERASE removes the
        # data_principal profile entirely; DE_IDENTIFY keeps a de-identified
        # copy (the pseudonym) so the fiduciary still has a record of the data
        # subject without the identifier.
        if action == "DE_IDENTIFY":
            cur.execute(
                "UPDATE data_principal SET user_id = %s WHERE fiduciary_id = %s AND user_id = %s",
                (token, fiduciary_id, user_id),
            )
            counts["data_principal"] = cur.rowcount
        else:
            cur.execute(
                "DELETE FROM data_principal WHERE fiduciary_id = %s AND user_id = %s",
                (fiduciary_id, user_id),
            )
            counts["data_principal"] = cur.rowcount
        cur.execute(
            "UPDATE purge_requests SET cms_erased_at = NOW() WHERE fiduciary_id = %s AND user_id = %s",
            (fiduciary_id, token),
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
    from ..security import pseudonym

    marker = f"erased:{pseudonym(f'{fiduciary_id}:{purpose_id}')}"
    with _cursor(cur) as cur:
        db.allow_consent_maintenance(cur)
        # DE_IDENTIFY: keep the entry so the consent's history is intact, but
        # blank the fields that name the purpose or the principal's choices.
        # ERASE: drop the entry entirely.
        if action == "DE_IDENTIFY":
            cur.execute(
                """
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
                WHERE fiduciary_id = %s AND user_id = %s
                  AND EXISTS (SELECT 1 FROM jsonb_array_elements(data_point_consents) q
                              WHERE lower(btrim(COALESCE(q->>'data_point_id', q->>'purpose_id', q->>'id'))) = %s)
                """,
                (canonical_purpose_id(purpose_id), marker, fiduciary_id, user_id, canonical_purpose_id(purpose_id)),
            )
        else:
            cur.execute(
                """
                UPDATE consent_records
                SET data_point_consents = (
                    SELECT COALESCE(jsonb_agg(p), '[]'::jsonb)
                    FROM jsonb_array_elements(data_point_consents) AS p
                    WHERE lower(btrim(COALESCE(p->>'data_point_id', p->>'purpose_id', p->>'id'))) IS DISTINCT FROM %s
                )
                WHERE fiduciary_id = %s AND user_id = %s
                  AND EXISTS (SELECT 1 FROM jsonb_array_elements(data_point_consents) q
                              WHERE lower(btrim(COALESCE(q->>'data_point_id', q->>'purpose_id', q->>'id'))) = %s)
                """,
                (canonical_purpose_id(purpose_id), fiduciary_id, user_id, canonical_purpose_id(purpose_id)),
            )
        return {"consent_records_touched": cur.rowcount}


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
        return db.to_jsonable(
            db.all(
                f"SELECT * FROM purge_requests WHERE {' AND '.join(where)} ORDER BY initiated_at DESC LIMIT %s OFFSET %s",
                params,
            )
        )

    def get_purge_request(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        row = db.one(
            f"SELECT * FROM purge_requests WHERE id = %s{scope}",
            (require(ctx.payload.get("id"), "id"), *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "Purge request not found.")
        return db.to_jsonable(row)

    def update_purge_status(self, ctx: RequestContext) -> dict:
        status = str(require(ctx.payload.get("status"), "status")).upper()
        if status not in PURGE_STATUSES:
            raise ApiError(400, "Bad Request", f"status must be one of {sorted(PURGE_STATUSES)}.")
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
            f"SELECT id, user_id, fiduciary_id, purpose_id, trigger_event, status, hold_until, app_id, assigned_operator_id, action FROM purge_requests WHERE id = %s{scope}",
            (request_id, *scope_params),
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
                    "SELECT 1 FROM purge_requests WHERE fiduciary_id = %s AND user_id = %s AND id <> %s"
                    " AND status = 'LEGAL_HOLD_APPLIED' AND (hold_until IS NULL OR hold_until > NOW()) LIMIT 1",
                    (fid, user_id, request_id),
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
        out = {"success": True, "status": status}
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


class GrievanceService(Service):
    def submit_grievance(self, ctx: RequestContext) -> dict:
        bind_principal_field(ctx, "user_id")
        user_id = require(ctx.payload.get("user_id"), "user_id")
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        grievance_type = str(require(ctx.payload.get("type"), "type")).strip().upper()
        # GR-02: categories are a fixed set the DPO routes on, not free text.
        if grievance_type not in GRIEVANCE_TYPES:
            raise ApiError(400, "Bad Request", f"type must be one of {sorted(GRIEVANCE_TYPES)}.")
        sla_days = 7 if grievance_type == "ERASURE_REQUEST" else 30
        consent_record_id = ctx.payload.get("consent_record_id")
        # GR-14: the complaint may be linked to the consent record it concerns.
        if consent_record_id:
            linked = db.one(
                "SELECT id FROM consent_records WHERE id = %s AND user_id = %s AND fiduciary_id = %s",
                (consent_record_id, user_id, fid),
            )
            if not linked:
                raise ApiError(
                    400,
                    "Bad Request",
                    "consent_record_id does not reference a consent record belonging to this principal and fiduciary.",
                )
        # UD-10 / GR-05: a short human-quotable reference the principal can raise
        # in follow-up contact. Collision-safe within a fiduciary via the unique
        # index on (fiduciary_id, reference_number).
        reference_number = self._next_reference(fid)
        # GR-03: the language the principal wrote in, so the grievance can be
        # handled and answered in it. A short code (Eighth Schedule / BCP 47).
        language = str(ctx.payload.get("language") or "").strip().lower() or None
        if language and (len(language) > 16 or not all(c.isalnum() or c == "-" for c in language)):
            raise ApiError(400, "Bad Request", "language must be a short language code such as 'hi' or 'ta'.")
        row = db.insert_returning(
            """
            INSERT INTO grievances
                (id, user_id, fiduciary_id, type, subject, description,
                 submission_timestamp, status, communication_log, attachments, due_date,
                 reference_number, consent_record_id, language)
            VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, NOW(), 'NEW', %s, %s,
                    NOW() + make_interval(days => %s), %s, %s, %s)
            RETURNING id, reference_number
            """,
            (
                user_id,
                fid,
                grievance_type,
                require(ctx.payload.get("subject"), "subject"),
                require(ctx.payload.get("description"), "description"),
                db.as_jsonb([]),
                db.as_jsonb(ctx.payload.get("attachments") or []),
                sla_days,
                reference_number,
                consent_record_id,
                language,
            ),
        )
        gid = str(row["id"])
        # GR-07: route by complaint CATEGORY. A fiduciary-configured rule
        # (set_grievance_routing) sends the category to a named department and
        # its officer; a category with no rule — or whose officer is no longer
        # ACTIVE — goes to the fiduciary's DPO. A fiduciary with neither leaves
        # the complaint NEW in the unassigned queue.
        target = db.one(
            """
            SELECT o.id, r.department FROM grievance_routing_rules r
            JOIN operators o ON o.id = r.operator_id AND o.status = 'ACTIVE'
            WHERE r.fiduciary_id = %s AND r.grievance_type = %s
            """,
            (fid, grievance_type),
        ) or db.one(
            "SELECT id, 'DPO' AS department FROM operators WHERE fiduciary_id = %s AND role = 'DPO'"
            " AND status = 'ACTIVE' ORDER BY created_at LIMIT 1",
            (fid,),
        )
        if target:
            department = str(target.get("department") or "DPO")
            entry = self._log_entry(ctx, "ASSIGNED", None, route=f"{grievance_type} -> {department}")
            # P7-05: keep the grievance observable in NEW — do not flip to
            # IN_PROGRESS in the same call, or the console's NEW filter and badge
            # become permanently empty. The assignee is notified below, so the
            # assignment still surfaces.
            db.execute(
                "UPDATE grievances SET assigned_dpo_user_id = %s, department = %s, last_updated_at = NOW(),"
                " communication_log = COALESCE(communication_log, '[]'::jsonb) || %s::jsonb WHERE id = %s",
                (str(target["id"]), department, db.as_jsonb([entry]), gid),
            )
            _notify_grievance_stage(user_id, fid, "ASSIGNED", language=language)
            # P7-05: the ASSIGNED stage notice above goes to the PRINCIPAL. The
            # person who must act gets a separate, officer-facing notice carrying
            # the grievance reference.
            _notify_grievance_assignee(str(target["id"]), fid, gid, reference_number, grievance_type)
        db.execute(
            "INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type, context)"
            " VALUES ('PRINCIPAL', %s, %s, 'GRIEVANCE_SUBMITTED', %s)",
            (user_id, fid, db.as_jsonb({"reference_number": reference_number, "language": language})),
        )
        log_event(
            user_id,
            fid,
            "APP",
            None,
            "GRIEVANCE_SUBMITTED",
            {"grievance_id": gid, "type": grievance_type, "reference_number": reference_number},
            purpose_id=consent_record_id,
            initiator="PRINCIPAL" if ctx.auth_via_principal_jwt else "INTEGRATOR",
            source_ip=ctx.source_ip,
        )
        return {
            "success": True,
            "grievance_id": gid,
            "reference_number": reference_number,
        }

    @staticmethod
    def _next_reference(fiduciary_id: str) -> str:
        """A short, human-quotable reference: GRV-<year>-<6 hex chars>.

        The per-fiduciary unique index means a collision falls back to a fresh
        value rather than failing the submission.
        """
        import uuid as uuidlib

        for _ in range(5):
            ref = f"GRV-{datetime.now(UTC).year}-{str(uuidlib.uuid4().hex[:6]).upper()}"
            if (
                db.one(
                    "SELECT 1 FROM grievances WHERE fiduciary_id = %s AND reference_number = %s LIMIT 1",
                    (fiduciary_id, ref),
                )
                is None
            ):
                return ref
        raise ApiError(409, "Conflict", "Could not allocate a unique grievance reference.")

    def get_grievance(self, ctx: RequestContext) -> dict:
        gid = ctx.payload.get("grievance_id") or ctx.payload.get("id")
        reference = ctx.payload.get("reference_number")
        # GR-05: a principal can quote the reference number instead of the id.
        if gid:
            where = ["id = %s"]
            params: list = [gid]
        else:
            where = ["reference_number = %s"]
            params = [require(reference, "grievance_id or reference_number")]
            if not ctx.fiduciary_id:
                where.append("fiduciary_id = %s")
                params.append(require(ctx.payload.get("fiduciary_id"), "fiduciary_id"))
        if ctx.fiduciary_id:
            where.append("fiduciary_id = %s")
            params.append(ctx.fiduciary_id)
        # GR-08: `grievance_id` alongside `id` — the console keys every row on it.
        row = db.one(f"SELECT *, id AS grievance_id FROM grievances WHERE {' AND '.join(where)}", params)
        if not row:
            raise ApiError(404, "Not Found", "Grievance not found.")
        ensure_principal_owns(ctx, row.get("user_id"), label="Grievance")
        return db.to_jsonable(row)

    def list_grievances(self, ctx: RequestContext) -> list[dict]:
        page, limit = page_limit(ctx.payload, 50)
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        where = ["fiduciary_id = %s"]
        params = [fid]
        if ctx.payload.get("status"):
            where.append("status = %s")
            params.append(ctx.payload["status"])
        params.extend([limit, (page - 1) * limit])
        return db.to_jsonable(
            db.all(
                # GR-08: the DPO queue reads grievance_id; without it every row threw.
                f"SELECT *, id AS grievance_id FROM grievances WHERE {' AND '.join(where)} ORDER BY submission_timestamp DESC LIMIT %s OFFSET %s",
                params,
            )
        )

    def list_user_grievances(self, ctx: RequestContext) -> list[dict]:
        bind_principal_field(ctx, "user_id")
        return db.to_jsonable(
            db.all(
                "SELECT *, id AS grievance_id FROM grievances WHERE fiduciary_id = %s AND user_id = %s ORDER BY submission_timestamp DESC",
                (require(resolve_fiduciary(ctx), "fiduciary_id"), require(ctx.payload.get("user_id"), "user_id")),
            )
        )

    @staticmethod
    def _log_entry(ctx: RequestContext, kind: str, text: str | None, **extra) -> dict:
        """GR-13: one timestamped entry in the grievance's action log."""
        return {
            "at": datetime.now(UTC).isoformat(),
            "kind": kind,
            "by": ctx.principal_user_id or ctx.actor_email or ("INTEGRATOR" if ctx.fiduciary_id else "SYSTEM"),
            "text": text,
            **extra,
        }

    def update_grievance_status(self, ctx: RequestContext) -> dict:
        gid = require(ctx.payload.get("grievance_id") or ctx.payload.get("id"), "grievance_id")
        status = str(require(ctx.payload.get("status"), "status")).upper()
        if status not in GRIEVANCE_STATUSES:
            raise ApiError(400, "Bad Request", f"status must be one of {sorted(GRIEVANCE_STATUSES)}.")
        resolution = ctx.payload.get("resolution_details")
        # GR-11: a grievance is closed only with a resolution summary for the principal.
        if status in {"RESOLVED", "CLOSED"} and not str(resolution or "").strip():
            raise ApiError(400, "Bad Request", "resolution_details is required to resolve or close a grievance.")
        scope, scope_params = tenant_filter(ctx)
        entry = self._log_entry(ctx, "STATUS_CHANGE", resolution, status=status)
        row = db.one(
            f"""
            UPDATE grievances SET status = %s, resolution_details = COALESCE(%s, resolution_details),
                   resolution_timestamp = CASE WHEN %s IN ('RESOLVED','CLOSED') THEN NOW() ELSE resolution_timestamp END,
                   communication_log = COALESCE(communication_log, '[]'::jsonb) || %s::jsonb,
                   last_updated_at = NOW()
            WHERE id = %s{scope}
            RETURNING user_id, fiduciary_id, reference_number, resolution_details, language
            """,
            (status, resolution, status, db.as_jsonb([entry]), gid, *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "Grievance not found.")
        # GR-10: the principal hears about every significant stage. GR-11: a
        # resolution notice carries the summary itself, not just the fact.
        context = None
        if status in {"RESOLVED", "CLOSED"}:
            context = {
                "grievance_id": str(gid),
                "reference_number": row.get("reference_number") or str(gid),
                "status_word": status.lower(),
                "resolution_details": row.get("resolution_details") or "",
            }
        _notify_grievance_stage(str(row["user_id"]), str(row["fiduciary_id"]), status, context, row.get("language"))
        log_event(
            ctx.actor_email or "DPO",
            str(row["fiduciary_id"]),
            "DPO_CONSOLE",
            None,
            "GRIEVANCE_STATUS_UPDATED",
            {"grievance_id": gid, "status": status},
            source_ip=ctx.source_ip,
        )
        return {"success": True}

    def assign_grievance(self, ctx: RequestContext) -> dict:
        # The grievance and the assignee must both belong to the grievance's tenant.
        gid = require(ctx.payload.get("grievance_id"), "grievance_id")
        operator_id = require(ctx.payload.get("operator_id"), "operator_id")
        officer = db.one("SELECT role, fiduciary_id FROM operators WHERE id = %s AND status = 'ACTIVE'", (operator_id,))
        if officer and not officer_can_handle_grievances(
            officer["role"], str(officer.get("fiduciary_id") or ctx.fiduciary_id or "") or None
        ):
            raise ApiError(400, "Bad Request", "The officer's role cannot act on grievances (needs grievance:write).")
        entry = self._log_entry(ctx, "ASSIGNED", None, operator_id=str(operator_id))
        # P7-05: assignment leaves the status as it is — the same outcome as the
        # auto-route in submit_grievance — so both paths agree. Work starting is a
        # separate, explicit update_grievance_status to IN_PROGRESS.
        row = db.one(
            """
            UPDATE grievances g SET assigned_dpo_user_id = o.id, last_updated_at = NOW(),
                   communication_log = COALESCE(g.communication_log, '[]'::jsonb) || %s::jsonb
            FROM operators o
            WHERE g.id = %s AND o.id = %s AND o.status = 'ACTIVE'
              AND (o.fiduciary_id = g.fiduciary_id OR o.role = 'ADMIN')
              AND (%s::uuid IS NULL OR g.fiduciary_id = %s::uuid)
            RETURNING g.user_id, g.fiduciary_id, g.reference_number, g.type, g.status, g.language, o.id AS operator_id
            """,
            (db.as_jsonb([entry]), gid, operator_id, ctx.fiduciary_id, ctx.fiduciary_id),
        )
        if not row:
            raise ApiError(404, "Not Found", "Grievance or operator not found.")
        fid = str(row["fiduciary_id"])
        _notify_grievance_stage(str(row["user_id"]), fid, "ASSIGNED", language=row.get("language"))
        # P7-05: the assignee hears about it too, with the grievance reference.
        _notify_grievance_assignee(str(row["operator_id"]), fid, str(gid), row.get("reference_number"), row.get("type"))
        log_event(
            ctx.actor_email or "DPO",
            fid,
            "DPO_CONSOLE",
            None,
            "GRIEVANCE_ASSIGNED",
            {"grievance_id": str(gid), "operator_id": str(row["operator_id"])},
            source_ip=ctx.source_ip,
        )
        return {"success": True, "status": row["status"]}

    def set_grievance_routing(self, ctx: RequestContext) -> dict:
        """GR-07: route a complaint category to a department and its officer.

        `remove: true` deletes the rule, so the category falls back to the DPO.
        The officer must be ACTIVE and belong to the fiduciary.
        """
        fid = str(require(resolve_fiduciary(ctx), "fiduciary_id"))
        grievance_type = str(require(ctx.payload.get("grievance_type"), "grievance_type")).strip().upper()
        if grievance_type not in GRIEVANCE_TYPES:
            raise ApiError(400, "Bad Request", f"grievance_type must be one of {sorted(GRIEVANCE_TYPES)}.")
        if ctx.payload.get("remove") is True:
            removed = db.execute(
                "DELETE FROM grievance_routing_rules WHERE fiduciary_id = %s AND grievance_type = %s",
                (fid, grievance_type),
            )
            details = {"grievance_type": grievance_type, "removed": bool(removed)}
        else:
            department = str(require(ctx.payload.get("department"), "department")).strip()
            if not department or len(department) > 100:
                raise ApiError(400, "Bad Request", "department must be 1 to 100 characters.")
            operator_id = require(ctx.payload.get("operator_id"), "operator_id")
            officer = db.one(
                "SELECT id, role FROM operators WHERE id = %s AND fiduciary_id = %s AND status = 'ACTIVE'",
                (operator_id, fid),
            )
            if not officer:
                raise ApiError(404, "Not Found", "Operator not found among this fiduciary's active operators.")
            if not officer_can_handle_grievances(officer["role"], fid):
                raise ApiError(
                    400, "Bad Request", "The officer's role cannot act on grievances (needs grievance:write)."
                )
            db.execute(
                """
                INSERT INTO grievance_routing_rules (fiduciary_id, grievance_type, department, operator_id, updated_by)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (fiduciary_id, grievance_type) DO UPDATE
                    SET department = EXCLUDED.department, operator_id = EXCLUDED.operator_id,
                        updated_by = EXCLUDED.updated_by, updated_at = NOW()
                """,
                (fid, grievance_type, department, str(officer["id"]), ctx.actor_email),
            )
            details = {"grievance_type": grievance_type, "department": department, "operator_id": str(officer["id"])}
        log_event(
            ctx.actor_email or "DPO",
            fid,
            "DPO_CONSOLE",
            None,
            "GRIEVANCE_ROUTING_UPDATED",
            details,
            source_ip=ctx.source_ip,
        )
        return {"success": True, **details}

    def list_grievance_routing(self, ctx: RequestContext) -> list[dict]:
        """GR-07: every category with its department and officer; unrouted
        categories are reported with the DPO fallback."""
        fid = str(require(resolve_fiduciary(ctx), "fiduciary_id"))
        rules = {
            r["grievance_type"]: r
            for r in db.all(
                "SELECT grievance_type, department, operator_id, updated_at FROM grievance_routing_rules"
                " WHERE fiduciary_id = %s",
                (fid,),
            )
        }
        return [
            db.to_jsonable(rules[t]) if t in rules else {"grievance_type": t, "department": "DPO", "operator_id": None}
            for t in sorted(GRIEVANCE_TYPES)
        ]

    def add_grievance_communication(self, ctx: RequestContext) -> dict:
        """GR-13: append a threaded entry (a message, a note, an action taken) to the
        grievance's action log without changing its status. A principal may add to
        their own grievance; the console and integrators to any in their tenant."""
        gid = require(ctx.payload.get("grievance_id") or ctx.payload.get("id"), "grievance_id")
        message = str(require(ctx.payload.get("message"), "message")).strip()
        if not message:
            raise ApiError(400, "Bad Request", "message must not be empty.")
        scope, scope_params = tenant_filter(ctx)
        if ctx.auth_via_principal_jwt:
            scope += " AND user_id = %s"
            scope_params.append(ctx.principal_user_id)
        entry = self._log_entry(ctx, str(ctx.payload.get("kind") or "MESSAGE").upper(), message)
        row = db.one(
            f"""
            UPDATE grievances SET communication_log = COALESCE(communication_log, '[]'::jsonb) || %s::jsonb,
                   last_updated_at = NOW()
            WHERE id = %s{scope}
            RETURNING id
            """,
            (db.as_jsonb([entry]), gid, *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "Grievance not found.")
        return {"success": True, "entry": entry}

    def submit_grievance_feedback(self, ctx: RequestContext) -> dict:
        """GR-12: the principal rates how their resolved grievance was handled."""
        bind_principal_field(ctx, "user_id")
        user_id = require(ctx.payload.get("user_id"), "user_id")
        gid = require(ctx.payload.get("grievance_id"), "grievance_id")
        try:
            rating = int(require(ctx.payload.get("rating"), "rating"))
        except (TypeError, ValueError):
            raise ApiError(400, "Bad Request", "rating must be an integer from 1 to 5.") from None
        if not 1 <= rating <= 5:
            raise ApiError(400, "Bad Request", "rating must be an integer from 1 to 5.")
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        row = db.one(
            """
            UPDATE grievances SET feedback_rating = %s, feedback_comment = %s, feedback_at = NOW(), last_updated_at = NOW()
            WHERE id = %s AND fiduciary_id = %s AND user_id = %s AND status IN ('RESOLVED', 'CLOSED')
              AND feedback_at IS NULL
            RETURNING id
            """,
            (rating, ctx.payload.get("comment"), gid, fid, user_id),
        )
        if not row:
            raise ApiError(
                409, "Conflict", "Feedback can be given once, by the complainant, after the grievance is resolved."
            )
        log_event(
            user_id,
            fid,
            "APP",
            None,
            "GRIEVANCE_FEEDBACK",
            {"grievance_id": gid, "rating": rating},
            initiator="PRINCIPAL" if ctx.auth_via_principal_jwt else "INTEGRATOR",
            source_ip=ctx.source_ip,
        )
        return {"success": True, "grievance_id": gid, "rating": rating}

    def upload_grievance_attachment(self, ctx: RequestContext) -> dict:
        """GR-04: attach supporting evidence to a grievance.

        The file arrives base64-encoded in the JSON body, is checked against an
        allow-list of types and the ATTACHMENT_MAX_BYTES limit, and is stored
        under the export path by its SHA-256, never by the caller's file name.
        """
        import base64
        import hashlib

        from ..config import settings

        gid = require(ctx.payload.get("grievance_id"), "grievance_id")
        content_type = str(require(ctx.payload.get("content_type"), "content_type")).lower()
        if content_type not in ATTACHMENT_TYPES:
            raise ApiError(400, "Bad Request", f"content_type must be one of {sorted(ATTACHMENT_TYPES)}.")
        file_name = str(require(ctx.payload.get("file_name"), "file_name"))[:255]
        try:
            data = base64.b64decode(str(require(ctx.payload.get("content_base64"), "content_base64")), validate=True)
        except ValueError:
            raise ApiError(400, "Bad Request", "content_base64 is not valid base64.") from None
        if not data or len(data) > settings.attachment_max_bytes:
            raise ApiError(413, "Payload Too Large", f"Attachments must be 1 to {settings.attachment_max_bytes} bytes.")
        scope, scope_params = tenant_filter(ctx)
        if ctx.auth_via_principal_jwt:
            scope += " AND user_id = %s"
            scope_params.append(ctx.principal_user_id)
        grievance = db.one(f"SELECT id, fiduciary_id FROM grievances WHERE id = %s{scope}", (gid, *scope_params))
        if not grievance:
            raise ApiError(404, "Not Found", "Grievance not found.")
        digest = hashlib.sha256(data).hexdigest()
        folder = settings.export_path / "attachments" / str(grievance["fiduciary_id"])
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / digest
        if not path.exists():
            path.write_bytes(data)
        uploader = ctx.principal_user_id or ctx.actor_email or "INTEGRATOR"
        row = db.insert_returning(
            """
            INSERT INTO grievance_attachments
                (grievance_id, fiduciary_id, file_name, content_type, size_bytes, sha256, storage_path, uploaded_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (gid, grievance["fiduciary_id"], file_name, content_type, len(data), digest, str(path), uploader),
        )
        attachment = {
            "attachment_id": str(row["id"]),
            "file_name": file_name,
            "sha256": digest,
            "size_bytes": len(data),
        }
        db.execute(
            "UPDATE grievances SET attachments = COALESCE(attachments, '[]'::jsonb) || %s::jsonb, last_updated_at = NOW() WHERE id = %s",
            (db.as_jsonb([attachment]), gid),
        )
        return {"success": True, **attachment}

    def get_grievance_attachment(self, ctx: RequestContext) -> dict:
        """GR-04: read back an attachment, with the same ownership rules as upload."""
        import base64
        from pathlib import Path

        aid = require(ctx.payload.get("attachment_id"), "attachment_id")
        scope, scope_params = tenant_filter(ctx, "a.fiduciary_id")
        if ctx.auth_via_principal_jwt:
            scope += " AND g.user_id = %s"
            scope_params.append(ctx.principal_user_id)
        row = db.one(
            f"""
            SELECT a.id, a.grievance_id, a.file_name, a.content_type, a.size_bytes, a.sha256,
                   a.storage_path, a.uploaded_by, a.created_at
            FROM grievance_attachments a JOIN grievances g ON g.id = a.grievance_id
            WHERE a.id = %s{scope}
            """,
            (aid, *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "Attachment not found.")
        try:
            data = Path(row["storage_path"]).read_bytes()
        except OSError:
            raise ApiError(410, "Gone", "The attachment file is no longer stored.") from None
        meta = db.to_jsonable({k: v for k, v in row.items() if k != "storage_path"})
        return {**meta, "attachment_id": str(row["id"]), "content_base64": base64.b64encode(data).decode("ascii")}


def _breach_user_ids(payload: dict) -> list[str] | None:
    """The principals a breach report names: a list and/or CSV text (one id
    per cell; a header cell 'user_id' is skipped). None when it names none."""
    ids: list[str] = []
    named = payload.get("affected_user_ids")
    if named is not None:
        if not isinstance(named, list):
            raise ApiError(400, "Bad Request", "affected_user_ids must be a list of principal ids.")
        ids.extend(str(u).strip() for u in named if str(u).strip())
    csv_text = payload.get("affected_user_ids_csv")
    if csv_text:
        for line in str(csv_text).splitlines():
            for cell in line.split(","):
                cell = cell.strip().strip('"').strip()
                if cell and cell.lower() not in {"user_id", "userid", "id"}:
                    ids.append(cell)
    return sorted(set(ids)) if ids else None


class BreachService(Service):
    def report_breach(self, ctx: RequestContext) -> dict:
        # S8-6: the console names a category (a BREACH_NOTIFICATION_* template
        # the DPO wrote) and the affected principals; both used to be dropped.
        category = str(ctx.payload.get("breach_category") or "").strip().upper()
        notification_type = ctx.payload.get("notification_type") or (
            f"BREACH_NOTIFICATION_{category}" if category else "BREACH_NOTIFICATION"
        )
        user_ids = _breach_user_ids(ctx.payload)
        row = db.insert_returning(
            """
            INSERT INTO breach_incidents
                (id, fiduciary_id, title, description, detected_at, affected_purpose_id,
                 affected_data_categories, actionable_steps, severity, status,
                 affected_principal_count, created_by_user_id, notification_type,
                 board_notification_deadline)
            VALUES (uuid_generate_v4(), %s, %s, %s, COALESCE(%s::timestamptz, NOW()), %s, %s,
                    %s, COALESCE(%s, 'MEDIUM'), 'OPEN', %s, %s, %s,
                    COALESCE(%s::timestamptz, NOW()) + INTERVAL '72 hours')
            RETURNING id, board_notification_deadline
            """,
            (
                require(resolve_fiduciary(ctx), "fiduciary_id"),
                require(ctx.payload.get("title"), "title"),
                require(ctx.payload.get("description"), "description"),
                ctx.payload.get("detected_at"),
                ctx.payload.get("affected_purpose_id"),
                db.as_jsonb(ctx.payload.get("affected_data_categories") or []),
                require(ctx.payload.get("actionable_steps"), "actionable_steps"),
                ctx.payload.get("severity"),
                int(ctx.payload.get("affected_principal_count") or 0),
                None,
                notification_type,
                ctx.payload.get("detected_at"),
            ),
        )
        log_event(
            authenticated_user_id(ctx) or "DPO",
            str(require(resolve_fiduciary(ctx), "fiduciary_id")),
            "DPO_CONSOLE",
            str(row["id"]),
            "BREACH_REPORTED",
            {"breach_id": str(row["id"]), "severity": ctx.payload.get("severity") or "MEDIUM"},
        )
        out = {
            "success": True,
            "breach_id": str(row["id"]),
            "board_notification_deadline": row["board_notification_deadline"].isoformat(),
            "affected_principal_count": 0,
            "notified": 0,
        }
        # s.8(6): intimate the affected principals as part of reporting, when
        # the report says who they are (named, or everyone under the purpose).
        if user_ids is not None or ctx.payload.get("affected_purpose_id"):
            notify_ctx = dataclasses.replace(
                ctx, payload={"id": str(row["id"]), **({"user_ids": user_ids} if user_ids is not None else {})}
            )
            sent = self.notify_affected_principals(notify_ctx)
            out["affected_principal_count"] = sent["affected_total"]
            out["notified"] = sent["notified"]
        return out

    def list_breaches(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(
            db.all(
                "SELECT * FROM breach_incidents WHERE fiduciary_id = %s ORDER BY reported_at DESC LIMIT %s",
                (require(resolve_fiduciary(ctx), "fiduciary_id"), int(ctx.payload.get("limit") or 50)),
            )
        )

    def get_breach(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        row = db.one(
            f"SELECT * FROM breach_incidents WHERE id = %s{scope}",
            (require(ctx.payload.get("id"), "id"), *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "Breach not found.")
        return db.to_jsonable(row)

    def update_breach_status(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        updated = db.execute(
            f"UPDATE breach_incidents SET status = %s, resolution_notes = COALESCE(%s, resolution_notes), last_updated_at = NOW() WHERE id = %s{scope}",
            (
                require(ctx.payload.get("status"), "status"),
                ctx.payload.get("resolution_notes"),
                require(ctx.payload.get("id"), "id"),
                *scope_params,
            ),
        )
        if updated == 0:
            raise ApiError(404, "Not Found", "Breach not found.")
        return {"success": True}

    def download_breach_report(self, ctx: RequestContext) -> dict:
        return self.get_breach(ctx)

    def _breach_row(self, ctx: RequestContext) -> dict:
        scope, scope_params = tenant_filter(ctx)
        row = db.one(
            f"SELECT * FROM breach_incidents WHERE id = %s{scope}",
            (require(ctx.payload.get("id") or ctx.payload.get("breach_id"), "id"), *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "Breach not found.")
        return row

    def notify_affected_principals(self, ctx: RequestContext) -> dict:
        """s.8(6) / Rule 7(1): intimate each affected Data Principal.

        The principals are the ones the caller names (`user_ids`), or - when
        none are named - every principal who ever granted the breach's
        affected purpose. Each gets one BREACH_NOTIFICATION (or the breach's own
        BREACH_NOTIFICATION_* category) carrying the breach's plain-language
        steps, and a breach_affected_principals row; a principal already
        notified for this breach is not notified twice.
        """
        breach = self._breach_row(ctx)
        fid = str(breach["fiduciary_id"])
        named = ctx.payload.get("user_ids")
        if named is not None:
            if not isinstance(named, list) or not all(isinstance(u, str) and u.strip() for u in named):
                raise ApiError(400, "Bad Request", "user_ids must be a list of principal ids.")
            user_ids = sorted({u.strip() for u in named})
        elif breach.get("affected_purpose_id"):
            user_ids = [
                str(r["user_id"])
                for r in db.all(
                    """
                    SELECT DISTINCT cr.user_id
                    FROM consent_records cr, LATERAL jsonb_array_elements(
                        CASE WHEN jsonb_typeof(cr.data_point_consents) = 'array'
                             THEN cr.data_point_consents ELSE '[]'::jsonb END) AS p
                    WHERE cr.fiduciary_id = %s AND cr.user_id NOT LIKE 'erased:%%'
                      AND tsi_point_purpose(p) = %s AND tsi_point_granted(p, FALSE)
                    ORDER BY cr.user_id
                    """,
                    (fid, canonical_purpose_id(breach["affected_purpose_id"])),
                )
            ]
        else:
            raise ApiError(
                400, "Bad Request", "Name the affected principals (user_ids); the breach records no affected purpose."
            )
        ntype = str(breach.get("notification_type") or "BREACH_NOTIFICATION")
        context = {
            "title": breach["title"],
            "actionable_steps": breach["actionable_steps"],
            "detected_at": breach["detected_at"].isoformat() if breach.get("detected_at") else None,
        }
        notified = 0
        with db.connection() as conn, conn.cursor() as cur:
            for user_id in user_ids:
                cur.execute(
                    "INSERT INTO breach_affected_principals (breach_id, user_id) VALUES (%s, %s)"
                    " ON CONFLICT (breach_id, user_id) DO NOTHING",
                    (breach["id"], user_id),
                )
                if cur.rowcount == 0:
                    continue
                cur.execute(
                    "INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type, context)"
                    " VALUES ('PRINCIPAL', %s, %s, %s, %s)",
                    (user_id, fid, ntype, db.as_jsonb(context)),
                )
                notified += 1
            cur.execute(
                "UPDATE breach_incidents SET affected_principal_count ="
                " (SELECT COUNT(*) FROM breach_affected_principals WHERE breach_id = %s),"
                " principals_notified_at = COALESCE(principals_notified_at, NOW()), last_updated_at = NOW()"
                " WHERE id = %s RETURNING affected_principal_count",
                (breach["id"], breach["id"]),
            )
            total = cur.fetchone()["affected_principal_count"]
        log_event(
            authenticated_user_id(ctx) or "DPO",
            fid,
            "DPO_CONSOLE",
            str(breach["id"]),
            "BREACH_PRINCIPALS_NOTIFIED",
            {"breach_id": str(breach["id"]), "notified": notified, "affected_total": total},
        )
        return {"success": True, "breach_id": str(breach["id"]), "notified": notified, "affected_total": total}

    def record_board_intimation(self, ctx: RequestContext) -> dict:
        """s.8(6) / Rule 7(2): record that the Data Protection Board was intimated.

        The 72-hour deadline column alone gave a clock with no way to stop it.
        The intimation reference (the Board's acknowledgement or the filing id)
        is mandatory; a late intimation is accepted and recorded as late.
        """
        breach = self._breach_row(ctx)
        if breach.get("board_notified_at"):
            raise ApiError(409, "Conflict", "The Board intimation for this breach is already recorded.")
        reference = str(require(ctx.payload.get("board_reference"), "board_reference")).strip()
        row = db.one(
            "UPDATE breach_incidents SET board_notified_at = COALESCE(%s::timestamptz, NOW()), board_reference = %s,"
            " board_notified_by = %s, last_updated_at = NOW() WHERE id = %s"
            " RETURNING board_notified_at, board_notified_at > board_notification_deadline AS late",
            (ctx.payload.get("intimated_at"), reference, authenticated_user_id(ctx), breach["id"]),
        )
        log_event(
            authenticated_user_id(ctx) or "DPO",
            str(breach["fiduciary_id"]),
            "DPO_CONSOLE",
            str(breach["id"]),
            "BREACH_BOARD_INTIMATED",
            {"breach_id": str(breach["id"]), "board_reference": reference, "late": bool(row["late"])},
        )
        return {
            "success": True,
            "breach_id": str(breach["id"]),
            "board_notified_at": row["board_notified_at"].isoformat(),
            "late": bool(row["late"]),
        }
