from __future__ import annotations

import logging
from datetime import UTC, datetime

from .. import db
from ..audit import log_event
from ..context import RequestContext
from ..errors import ApiError
from .base import Service, bind_principal_field, ensure_principal_owns, page_limit, require, tenant_filter
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


def _notify_grievance_stage(user_id: str, fiduciary_id: str, stage: str) -> None:
    notice = GRIEVANCE_STAGE_NOTICES.get(stage)
    if notice:
        db.execute(
            "INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type) VALUES ('PRINCIPAL', %s, %s, %s)",
            (user_id, fiduciary_id, notice),
        )


def erase_cms_copy(fiduciary_id: str, user_id: str, action: str = "ERASE") -> dict[str, int]:
    """SA-13: irreversibly de-identify what the CMS itself holds about a principal.

    The processor deletes the business data; this removes the CMS's own copy of
    the identifier. Every row keyed by the principal is re-keyed to a keyed hash
    (HMAC with the deployment's lookup salt), so the consent evidence trail stays
    countable but no longer names anyone, and free-text grievance content is
    blanked. SEC-15: the covered set is every table/schema column that stores a
    principal identifier (see ERASURE_TARGETS, kept next to the test that
    enumerates them). The audit log already stores only the pseudonym.

    PL-03: the caller passes `action` — the value stored on the purge request
    (from the retention policy or the closure). ERASE deletes the data_principal
    profile outright; DE_IDENTIFY re-keys it to the pseudonym instead, so the
    two BRD dispositions genuinely behave differently in the CMS rather than
    both boiling down to the same hard delete.
    """
    from ..security import pseudonym

    token = f"erased:{pseudonym(f'{fiduciary_id}:{user_id}')}"
    counts: dict[str, int] = {}
    with db.connection() as conn, conn.cursor() as cur:
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
            elif current.get("assigned_operator_id"):
                raise ApiError(
                    403, "Forbidden", "This purge request is assigned to an operator; it cannot be closed by an API key."
                )
        elif ctx.operator_id and current.get("assigned_operator_id"):
            # SEC-04: the delegation binds the console too — an operator other
            # than the assignee may not update or confirm the request.
            if str(current["assigned_operator_id"]) != ctx.operator_id:
                raise ApiError(403, "Forbidden", "This purge request is assigned to another operator.")
        # CW-11: data under an unexpired legal hold may not be reported deleted.
        if (
            current["status"] == "LEGAL_HOLD_APPLIED"
            and status in {"PURGE_COMPLETED", "COMPLETED"}
            and current.get("hold_until")
            and current["hold_until"] > datetime.now(UTC)
        ):
            raise ApiError(409, "Conflict", "This request is under a legal hold until its retention period ends.")
        completed = status in {"PURGE_COMPLETED", "COMPLETED"}
        db.execute(
            """
            UPDATE purge_requests SET status = %s, details = COALESCE(%s, details), last_updated_at = NOW(),
                   completion_evidence = COALESCE(%s, completion_evidence),
                   completed_at = CASE WHEN %s THEN NOW() ELSE completed_at END
            WHERE id = %s
            """,
            (status, details, db.as_jsonb(evidence) if evidence else None, completed, request_id),
        )
        fid, user_id = str(current["fiduciary_id"]), str(current["user_id"])
        erased = None
        # SA-13: once a whole-account erasure is confirmed done (and nothing for
        # this principal is still held by law), the CMS de-identifies its own copy.
        # PL-03: the disposition comes from the purge request's own `action` —
        # ERASE deletes the profile, DE_IDENTIFY keeps the pseudonym — so the CMS
        # no longer treats both as identical.
        if completed and current["trigger_event"] == "ErasureRequest" and current["purpose_id"] == "ALL":
            still_held = db.one(
                "SELECT 1 FROM purge_requests WHERE fiduciary_id = %s AND user_id = %s AND status = 'LEGAL_HOLD_APPLIED' LIMIT 1",
                (fid, user_id),
            )
            if not still_held:
                erased = erase_cms_copy(fid, user_id, action=str(current.get("action") or "ERASE").upper())
        log_event(
            ctx.actor_email or ("INTEGRATOR" if ctx.permissions else "DPO"),
            fid,
            "DPO_CONSOLE" if ctx.category == "admin" else "APP",
            None,
            "PURGE_STATUS_UPDATED",
            {"purge_request_id": request_id, "status": status, "evidence": evidence, "cms_copy_erased": bool(erased)},
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
        row = db.insert_returning(
            """
            INSERT INTO grievances
                (id, user_id, fiduciary_id, type, subject, description,
                 submission_timestamp, status, communication_log, attachments, due_date,
                 reference_number, consent_record_id)
            VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, NOW(), 'NEW', %s, %s,
                    NOW() + make_interval(days => %s), %s, %s)
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
            ),
        )
        gid = str(row["id"])
        db.execute(
            "INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type) VALUES ('PRINCIPAL', %s, %s, 'GRIEVANCE_SUBMITTED')",
            (user_id, fid),
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
        row = db.one(f"SELECT * FROM grievances WHERE {' AND '.join(where)}", params)
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
                f"SELECT * FROM grievances WHERE {' AND '.join(where)} ORDER BY submission_timestamp DESC LIMIT %s OFFSET %s",
                params,
            )
        )

    def list_user_grievances(self, ctx: RequestContext) -> list[dict]:
        bind_principal_field(ctx, "user_id")
        return db.to_jsonable(
            db.all(
                "SELECT * FROM grievances WHERE fiduciary_id = %s AND user_id = %s ORDER BY submission_timestamp DESC",
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
            RETURNING user_id, fiduciary_id
            """,
            (status, resolution, status, db.as_jsonb([entry]), gid, *scope_params),
        )
        if not row:
            raise ApiError(404, "Not Found", "Grievance not found.")
        # GR-10: the principal hears about every significant stage.
        _notify_grievance_stage(str(row["user_id"]), str(row["fiduciary_id"]), status)
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
        entry = self._log_entry(ctx, "ASSIGNED", None, operator_id=str(operator_id))
        row = db.one(
            """
            UPDATE grievances g SET assigned_dpo_user_id = o.id, status = 'IN_PROGRESS', last_updated_at = NOW(),
                   communication_log = COALESCE(g.communication_log, '[]'::jsonb) || %s::jsonb
            FROM operators o
            WHERE g.id = %s AND o.id = %s AND o.status = 'ACTIVE'
              AND (o.fiduciary_id = g.fiduciary_id OR o.role = 'ADMIN')
              AND (%s::uuid IS NULL OR g.fiduciary_id = %s::uuid)
            RETURNING g.user_id, g.fiduciary_id
            """,
            (db.as_jsonb([entry]), gid, operator_id, ctx.fiduciary_id, ctx.fiduciary_id),
        )
        if not row:
            raise ApiError(404, "Not Found", "Grievance or operator not found.")
        _notify_grievance_stage(str(row["user_id"]), str(row["fiduciary_id"]), "ASSIGNED")
        return {"success": True}

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


class BreachService(Service):
    def report_breach(self, ctx: RequestContext) -> dict:
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
                ctx.payload.get("notification_type", "BREACH_NOTIFICATION"),
                ctx.payload.get("detected_at"),
            ),
        )
        return {
            "success": True,
            "breach_id": str(row["id"]),
            "board_notification_deadline": row["board_notification_deadline"].isoformat(),
        }

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
