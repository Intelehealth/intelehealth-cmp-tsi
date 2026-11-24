from __future__ import annotations

from datetime import UTC, datetime

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    bind_principal_field,
    ensure_principal_owns,
    page_limit,
    require,
)
from dpdpcms_py.modules.administration.api import resolve_fiduciary
from dpdpcms_py.modules.audit_logging.ledger import log_event
from dpdpcms_py.modules.grievance.common import GRIEVANCE_TYPES, _notify_grievance_assignee, _notify_grievance_stage

# GR-02: the complaint categories the rights portal offers, plus the two
# consent-specific ones the BRD names (consent and data handling).
GRIEVANCE_CHANNELS = ("PORTAL", "EMAIL", "PHONE", "LETTER", "IN_PERSON", "OTHER")


# A grievance with its principal decrypted; bind *db.bind_key() first.
_GRIEVANCE_COLUMNS = f"*, id AS grievance_id, {pii.dec_sql('user_id_enc')} AS user_id"


class ComplaintHandlers:
    def submit_grievance(self, ctx: RequestContext) -> dict:
        bind_principal_field(ctx, "user_id")
        user_id = require(ctx.payload.get("user_id"), "user_id")
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        grievance_type = str(require(ctx.payload.get("type"), "type")).strip().upper()
        # GR-02: categories are a fixed set the DPO routes on, not free text.
        if grievance_type not in GRIEVANCE_TYPES:
            raise ApiError(400, "Bad Request", f"type must be one of {sorted(GRIEVANCE_TYPES)}.")
        sla_days = 7 if grievance_type == "ERASURE_REQUEST" else 30
        # How the grievance arrived. Only a console operator logging an offline
        # complaint may name a channel; principals and API callers are PORTAL.
        channel = "PORTAL"
        if ctx.operator_id and ctx.payload.get("channel"):
            channel = str(ctx.payload["channel"]).strip().upper()
            if channel not in GRIEVANCE_CHANNELS:
                raise ApiError(400, "Bad Request", f"channel must be one of {list(GRIEVANCE_CHANNELS)}.")
        consent_record_id = ctx.payload.get("consent_record_id")
        # GR-14: the complaint may be linked to the consent record it concerns.
        if consent_record_id:
            linked = db.one(
                f"SELECT id FROM consent_records WHERE id = %s AND {pii.match_sql('user_id')} AND fiduciary_id = %s",
                (consent_record_id, *pii.hmac_params(user_id), fid),
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
            f"""
            INSERT INTO grievances
                (id, user_id_enc, user_id_hmac, fiduciary_id, type, subject, description,
                 submission_timestamp, status, communication_log, attachments, due_date,
                 reference_number, consent_record_id, language, channel)
            VALUES (uuid_generate_v4(), {pii.PID_VALUES}, %s, %s, %s, %s, NOW(), 'NEW', %s, %s,
                    NOW() + make_interval(days => %s), %s, %s, %s, %s)
            RETURNING id, reference_number
            """,
            (
                *pii.pid_params(user_id),
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
                channel,
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
            "INSERT INTO notifications (recipient_type, recipient_id_enc, recipient_id_hmac, fiduciary_id,"
            f" notification_type, context) VALUES ('PRINCIPAL', {pii.PID_VALUES}, %s, 'GRIEVANCE_SUBMITTED', %s)",
            (*pii.pid_params(user_id), fid, db.as_jsonb({"reference_number": reference_number, "language": language})),
        )
        log_event(
            user_id,
            fid,
            "APP",
            None,
            "GRIEVANCE_SUBMITTED",
            {"grievance_id": gid, "type": grievance_type, "reference_number": reference_number, "channel": channel},
            purpose_id=consent_record_id,
            # A grievance a console operator logs is attributed to that operator.
            initiator=(
                f"OPERATOR:{ctx.operator_id}"
                if ctx.operator_id
                else "PRINCIPAL"
                if ctx.auth_via_principal_jwt
                else "INTEGRATOR"
            ),
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
        row = db.one(
            f"SELECT {_GRIEVANCE_COLUMNS} FROM grievances WHERE {' AND '.join(where)}", (*db.bind_key(), *params)
        )
        if not row:
            raise ApiError(404, "Not Found", "Grievance not found.")
        ensure_principal_owns(ctx, row.get("user_id"), label="Grievance")
        return pii.principal_row(ctx, row, "user_id")

    def list_grievances(self, ctx: RequestContext) -> list[dict]:
        page, limit = page_limit(ctx.payload, 50)
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        where = ["fiduciary_id = %s"]
        params = [fid]
        if ctx.payload.get("status"):
            where.append("status = %s")
            params.append(ctx.payload["status"])
        # Search by principal: the whole identifier through its HMAC (trimmed,
        # case kept); an encrypted column cannot be substring-matched.
        if str(ctx.payload.get("user_id") or "").strip():
            where.append(pii.match_sql("user_id"))
            params.extend(pii.hmac_params(str(ctx.payload["user_id"])))
        params.extend([limit, (page - 1) * limit])
        rows = db.all(
            # GR-08: the DPO queue reads grievance_id; without it every row threw.
            f"SELECT {_GRIEVANCE_COLUMNS} FROM grievances WHERE {' AND '.join(where)}"
            " ORDER BY submission_timestamp DESC LIMIT %s OFFSET %s",
            (*db.bind_key(), *params),
        )
        return [pii.principal_row(ctx, row, "user_id") for row in rows]

    def list_user_grievances(self, ctx: RequestContext) -> list[dict]:
        bind_principal_field(ctx, "user_id")
        rows = db.all(
            f"SELECT {_GRIEVANCE_COLUMNS} FROM grievances WHERE fiduciary_id = %s AND {pii.match_sql('user_id')}"
            " ORDER BY submission_timestamp DESC",
            (
                *db.bind_key(),
                require(resolve_fiduciary(ctx), "fiduciary_id"),
                *pii.hmac_params(require(ctx.payload.get("user_id"), "user_id")),
            ),
        )
        return [pii.principal_row(ctx, row, "user_id") for row in rows]

    @staticmethod
    def _log_entry(ctx: RequestContext, kind: str, text: str | None, **extra) -> dict:
        """GR-13: one timestamped entry in the grievance's action log."""
        return {
            "at": datetime.now(UTC).isoformat(),
            "kind": kind,
            # A principal is recorded as PRINCIPAL, never by id: the log is JSON,
            # outside the encrypted columns, and the grievance's own encrypted
            # user_id already says who they are.
            "by": "PRINCIPAL"
            if ctx.principal_user_id
            else ctx.actor_email or ("INTEGRATOR" if ctx.fiduciary_id else "SYSTEM"),
            "text": text,
            **extra,
        }
