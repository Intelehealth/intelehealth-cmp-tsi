from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    Service,
    canonical_purpose_id,
    require,
    tenant_filter,
)
from dpdpcms_py.modules.administration.api import authenticated_user_id, resolve_fiduciary
from dpdpcms_py.modules.audit_logging.ledger import log_event

# Rule 7(1) contents of the intimation to principals, and the Rule 7(2)(b)
# detailed report to the Board.
BREACH_RULE7_FIELDS = (
    "likely_consequences",
    "mitigation_measures",
    "contact_point",
    "circumstances",
    "cause_findings",
    "remedial_measures",
)


BREACH_DETAILED_REPORT_FIELDS = ("circumstances", "mitigation_measures", "cause_findings", "remedial_measures")


def _breach_text(payload: dict, key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _fmt_time(value: object) -> str:
    return value.isoformat() if hasattr(value, "isoformat") else str(value or "-")


def breach_report_lines(breach: dict) -> list[str]:
    """The lines of the Rule 7 breach report PDF (P12-12)."""
    # P13-02: 'late' is judged on the recorded time; the DPO's assertion is
    # printed beside it as unverified context.
    late = late_as_asserted = None
    deadline = breach.get("board_notification_deadline")
    recorded = breach.get("board_notified_at")
    asserted = breach.get("board_intimated_at_asserted")
    if deadline and recorded:
        late = recorded > deadline
    if deadline and asserted:
        late_as_asserted = asserted > deadline
    categories = breach.get("affected_data_categories") or []
    return [
        f"Breach id: {breach['id']}",
        f"Severity: {breach.get('severity') or '-'}    Status: {breach.get('status') or '-'}",
        f"Detected: {_fmt_time(breach.get('detected_at'))}",
        f"Reported in the CMS: {_fmt_time(breach.get('reported_at'))}",
        "",
        "Nature, extent and timing (Rule 7(1)(a))",
        str(breach.get("description") or "-"),
        f"Affected purpose: {breach.get('affected_purpose_id') or '-'}",
        f"Affected data categories: {', '.join(str(c) for c in categories) if categories else '-'}",
        f"Affected principals: {breach.get('affected_principal_count') or 0}",
        "",
        "Likely consequences (Rule 7(1)(b))",
        str(breach.get("likely_consequences") or "Not yet recorded."),
        "",
        "Mitigation measures implemented (Rule 7(1)(c))",
        str(breach.get("mitigation_measures") or "Not yet recorded."),
        "",
        "Safety measures the Data Principal may take (Rule 7(1)(d))",
        str(breach.get("actionable_steps") or "-"),
        "",
        "Contact point (Rule 7(1)(e))",
        str(breach.get("contact_point") or "Not yet recorded."),
        "",
        "Intimation of affected principals",
        f"Principals notified from: {_fmt_time(breach.get('principals_notified_at'))}",
        "",
        "Data Protection Board intimation (Rule 7(2)(a))",
        f"72-hour deadline: {_fmt_time(deadline)}",
        f"Intimation recorded in the CMS: {_fmt_time(breach.get('board_notified_at'))}",
        f"Intimation time asserted by the DPO: {_fmt_time(breach.get('board_intimated_at_asserted'))}",
        f"Board reference: {breach.get('board_reference') or '-'}",
        f"Late (by the recorded time): {'-' if late is None else ('yes' if late else 'no')}",
        f"Late by the DPO's asserted time (unverified): {'-' if late_as_asserted is None else ('yes' if late_as_asserted else 'no')}",
        "",
        "Detailed report (Rule 7(2)(b))",
        f"Submitted: {_fmt_time(breach.get('board_report_submitted_at'))}",
        "Events, circumstances and reasons:",
        str(breach.get("circumstances") or "Not yet recorded."),
        "Findings regarding the person who caused the breach:",
        str(breach.get("cause_findings") or "Not yet recorded."),
        "Remedial measures to prevent recurrence:",
        str(breach.get("remedial_measures") or "Not yet recorded."),
        "",
        "Resolution notes",
        str(breach.get("resolution_notes") or "-"),
    ]


def _parse_asserted_time(value: object, field: str) -> datetime | None:
    """A caller-asserted timestamp as an aware datetime (naive reads as UTC)."""
    if value in (None, ""):
        return None
    try:
        when = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApiError(400, "Bad Request", f"{field} must be an ISO 8601 timestamp.") from exc
    return when if when.tzinfo else when.replace(tzinfo=UTC)


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
        # The 72-hour clock runs from detection, so detection cannot be later
        # than the report itself.
        detected = _parse_asserted_time(ctx.payload.get("detected_at"), "detected_at")
        if detected is not None and detected > datetime.now(UTC):
            raise ApiError(400, "Bad Request", "detected_at cannot be in the future.")
        row = db.insert_returning(
            """
            INSERT INTO breach_incidents
                (id, fiduciary_id, title, description, detected_at, affected_purpose_id,
                 affected_data_categories, actionable_steps, severity, status,
                 affected_principal_count, created_by_user_id, notification_type,
                 board_notification_deadline, likely_consequences, mitigation_measures, contact_point)
            VALUES (uuid_generate_v4(), %s, %s, %s, COALESCE(%s::timestamptz, NOW()), %s, %s,
                    %s, COALESCE(%s, 'MEDIUM'), 'OPEN', %s, %s, %s,
                    COALESCE(%s::timestamptz, NOW()) + INTERVAL '72 hours', %s, %s, %s)
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
                _breach_text(ctx.payload, "likely_consequences"),
                _breach_text(ctx.payload, "mitigation_measures"),
                _breach_text(ctx.payload, "contact_point"),
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
        """Status and resolution, plus the Rule 7 contents as they become known:
        the Rule 7(1) intimation fields and the Rule 7(2)(b) detailed report.
        `submit_detailed_report` stamps when that report went to the Board; it
        needs every Rule 7(2)(b) field and can be stamped once."""
        scope, scope_params = tenant_filter(ctx)
        fields = ["status = %s", "resolution_notes = COALESCE(%s, resolution_notes)", "last_updated_at = NOW()"]
        params: list[object] = [require(ctx.payload.get("status"), "status"), ctx.payload.get("resolution_notes")]
        for key in BREACH_RULE7_FIELDS:
            if _breach_text(ctx.payload, key) is not None:
                fields.append(f"{key} = %s")
                params.append(_breach_text(ctx.payload, key))
        if ctx.payload.get("submit_detailed_report"):
            breach = self._breach_row(ctx)
            if breach.get("board_report_submitted_at"):
                raise ApiError(409, "Conflict", "The Rule 7(2) detailed report for this breach is already recorded.")
            missing = [
                key
                for key in BREACH_DETAILED_REPORT_FIELDS
                if not (_breach_text(ctx.payload, key) or str(breach.get(key) or "").strip())
            ]
            if missing:
                raise ApiError(400, "Bad Request", f"The Rule 7(2) detailed report still needs {missing}.")
            fields.append("board_report_submitted_at = NOW()")
        updated = db.execute(
            f"UPDATE breach_incidents SET {', '.join(fields)} WHERE id = %s{scope}",
            (*params, require(ctx.payload.get("id"), "id"), *scope_params),
        )
        if updated == 0:
            raise ApiError(404, "Not Found", "Breach not found.")
        return {"success": True}

    def download_breach_report(self, ctx: RequestContext) -> bytes:
        """P12-12: the Rule 7 breach report as a real PDF, rendered server-side
        (it used to be get_breach's JSON saved under a .pdf name)."""
        from dpdpcms_py.kernel.pdfgen import text_pdf

        breach = self._breach_row(ctx)
        return text_pdf(f"Personal data breach report - {breach['title']}", breach_report_lines(breach))

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
            # One row per principal (by HMAC), decrypted; erased principals
            # hold an `erased:` placeholder and are not intimated.
            holders = db.all(
                f"""
                SELECT {pii.dec_sql("h.user_id_enc")} AS user_id FROM (
                    SELECT DISTINCT ON (cr.user_id_hmac) cr.user_id_enc
                    FROM consent_records cr, LATERAL jsonb_array_elements(
                        CASE WHEN jsonb_typeof(cr.data_point_consents) = 'array'
                             THEN cr.data_point_consents ELSE '[]'::jsonb END) AS p
                    WHERE cr.fiduciary_id = %s AND tsi_point_purpose(p) = %s AND tsi_point_granted(p, FALSE)
                    ORDER BY cr.user_id_hmac
                ) h
                """,
                (*db.bind_key(), fid, canonical_purpose_id(breach["affected_purpose_id"])),
            )
            user_ids = sorted(
                str(r["user_id"]) for r in holders if not str(r["user_id"] or "erased:").startswith("erased:")
            )
        else:
            raise ApiError(
                400, "Bad Request", "Name the affected principals (user_ids); the breach records no affected purpose."
            )
        ntype = str(breach.get("notification_type") or "BREACH_NOTIFICATION")
        # Rule 7(1): what happened, its likely consequences, what was done, what
        # the principal can do, and whom to contact.
        context = {
            "title": breach["title"],
            "description": breach["description"],
            "actionable_steps": breach["actionable_steps"],
            "detected_at": breach["detected_at"].isoformat() if breach.get("detected_at") else None,
            "likely_consequences": breach.get("likely_consequences") or "still being assessed",
            "mitigation_measures": breach.get("mitigation_measures") or "still being assessed",
            "contact_point": breach.get("contact_point") or "our Data Protection Officer",
        }
        notified = 0
        with db.connection() as conn, conn.cursor() as cur:
            for user_id in user_ids:
                cur.execute(
                    f"INSERT INTO breach_affected_principals (breach_id, user_id_enc, user_id_hmac)"
                    f" VALUES (%s, {pii.PID_VALUES}) ON CONFLICT (breach_id, user_id_hmac) DO NOTHING",
                    (breach["id"], *pii.pid_params(user_id)),
                )
                if cur.rowcount == 0:
                    continue
                cur.execute(
                    "INSERT INTO notifications (recipient_type, recipient_id_enc, recipient_id_hmac, fiduciary_id,"
                    f" notification_type, context) VALUES ('PRINCIPAL', {pii.PID_VALUES}, %s, %s, %s)",
                    (*pii.pid_params(user_id), fid, ntype, db.as_jsonb(context)),
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

        P12-04: board_notified_at is the server's time of recording, never the
        caller's. An intimation made earlier through another channel may be
        asserted as intimated_at; it is kept in its own column and must fall
        between detection and now.

        P13-02: 'late' is decided by the recorded time only. An assertion is
        unverified, so it is reported beside it as late_as_asserted - context
        for the Board, never a way to turn a late record into an on-time one.
        """
        breach = self._breach_row(ctx)
        if breach.get("board_notified_at"):
            raise ApiError(409, "Conflict", "The Board intimation for this breach is already recorded.")
        reference = str(require(ctx.payload.get("board_reference"), "board_reference")).strip()
        asserted = _parse_asserted_time(ctx.payload.get("intimated_at"), "intimated_at")
        if asserted is not None:
            now = datetime.now(UTC)
            detected = breach["detected_at"]
            if asserted > now or asserted < detected:
                raise ApiError(
                    400,
                    "Bad Request",
                    "intimated_at must fall between the breach's detection and now.",
                )
        row = db.one(
            "UPDATE breach_incidents SET board_notified_at = NOW(), board_intimated_at_asserted = %s,"
            " board_reference = %s, board_notified_by = %s, last_updated_at = NOW() WHERE id = %s"
            " RETURNING board_notified_at, board_intimated_at_asserted,"
            " board_notified_at > board_notification_deadline AS late,"
            " board_intimated_at_asserted > board_notification_deadline AS late_as_asserted",
            (asserted, reference, authenticated_user_id(ctx), breach["id"]),
        )
        log_event(
            authenticated_user_id(ctx) or "DPO",
            str(breach["fiduciary_id"]),
            "DPO_CONSOLE",
            str(breach["id"]),
            "BREACH_BOARD_INTIMATED",
            {
                "breach_id": str(breach["id"]),
                "board_reference": reference,
                "recorded_at": row["board_notified_at"].isoformat(),
                "intimated_at_asserted": asserted.isoformat() if asserted else None,
                "late": bool(row["late"]),
                "late_as_asserted": row["late_as_asserted"],
            },
        )
        return {
            "success": True,
            "breach_id": str(breach["id"]),
            "board_notified_at": row["board_notified_at"].isoformat(),
            "intimated_at_asserted": asserted.isoformat() if asserted else None,
            "late": bool(row["late"]),
            "late_as_asserted": row["late_as_asserted"],
        }
