from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.security import principal_token
from dpdpcms_py.kernel.service import (
    bind_principal_field,
    canonical_purpose_id,
    csv_safe,
    page_limit,
    point_purpose_id,
    require,
)
from dpdpcms_py.modules.audit_logging.ledger import log_event
from dpdpcms_py.modules.consent_lifecycle.common import (
    _CONSENT_COLUMNS,
    _USER_MATCH,
    _consent_keys,
    _consent_row,
    _fid,
    _point_granted,
    _purpose_names,
    _require_console_operator,
)

# A principal reference: the hex HMAC of its identifier (data_principal.user_id_hmac).
USER_REF_RE = re.compile(r"[0-9a-f]{64}")


class HistoryHandlers:
    def list_consent_history(self, ctx: RequestContext) -> list[dict]:
        bind_principal_field(ctx, "user_id")
        payload = ctx.payload
        page, limit = page_limit(payload)
        if payload.get("user_ref") is not None:
            # A console operator holds only the masked id and its reference (the
            # lookup HMAC list_principals hands out); it reads by reference, in its
            # own tenant, with no reveal. An API key or principal names the id.
            _require_console_operator(ctx)
            user_ref = str(payload["user_ref"])
            if not USER_REF_RE.fullmatch(user_ref):
                raise ApiError(400, "Bad Request", "Invalid 'user_ref'.")
            where = ["user_id_hmac = %s", "fiduciary_id = %s"]
            params: list[Any] = [*_consent_keys(), user_ref, _fid(ctx)]
        else:
            where = [_USER_MATCH, "fiduciary_id = %s"]
            params = [*_consent_keys(), *pii.hmac_params(require(payload.get("user_id"), "user_id")), _fid(ctx)]
        # UD-03: search and filter by purpose, date and status.
        if payload.get("purpose_id"):
            where.append(
                # P12-10: the same alias rule as point_purpose_id (an empty
                # data_point_id is skipped), via db/27's tsi_point_purpose.
                "EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(data_point_consents) = 'array' "
                "THEN data_point_consents ELSE '[]'::jsonb END) p WHERE tsi_point_purpose(p) = %s)"
            )
            params.append(canonical_purpose_id(payload["purpose_id"]))
        if payload.get("status"):
            status = str(payload["status"]).upper()
            if status == "ACTIVE":
                where.append("is_active_consent IS TRUE")
            else:
                where.append("consent_status_general = %s")
                params.append(status)
        if payload.get("start_date"):
            where.append("timestamp >= %s::timestamptz")
            params.append(payload["start_date"])
        if payload.get("end_date"):
            where.append("timestamp <= %s::timestamptz")
            params.append(payload["end_date"])
        rows = db.all(
            f"SELECT {_CONSENT_COLUMNS} FROM consent_records WHERE {' AND '.join(where)}"
            " ORDER BY timestamp DESC LIMIT %s OFFSET %s",
            [*params, limit, (page - 1) * limit],
        )
        out = [_consent_row(ctx, row) for row in rows]
        # The wallet sync token is a principal credential: only the principal's own
        # session receives it, never an integrator or console reading the history.
        if ctx.auth_via_principal_jwt:
            for item, row in zip(out, rows, strict=True):
                item["sync_token"] = principal_token(str(item["fiduciary_id"]), row["user_id"])
        return out

    def export_consent_history(self, ctx: RequestContext) -> str | bytes:
        """UD-04: a principal downloads their consent history as CSV or PDF (format=pdf).

        A principal token is held to its own history. An integrator key may export
        any principal of its own fiduciary — it acts for that fiduciary, which
        answers a principal's access request — but never another tenant's.
        """
        import csv
        import io

        bind_principal_field(ctx, "user_id")
        fid = _fid(ctx)
        user_id = require(ctx.payload.get("user_id"), "user_id")
        rows = db.all(
            f"""
            SELECT cr.timestamp, cr.policy_id, cr.policy_version, cr.language_selected,
                   cr.consent_status_general, cr.is_active_consent, cr.data_point_consents,
                   p.policy_content
            FROM consent_records cr
            LEFT JOIN consent_policies p
                   ON p.id = cr.policy_id AND p.version = cr.policy_version AND p.fiduciary_id = cr.fiduciary_id
            WHERE cr.{_USER_MATCH} AND cr.fiduciary_id = %s
            ORDER BY cr.timestamp DESC
            """,
            (*pii.hmac_params(user_id), fid),
        )
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["timestamp", "policy_id", "policy_version", "language", "status", "active", "purposes"])
        for row in rows:
            points = row.get("data_point_consents") or []
            purposes = ", ".join(
                point_purpose_id(p) + ("" if _point_granted(p) else ":withdrawn") for p in points if isinstance(p, dict)
            )
            writer.writerow(
                [
                    csv_safe(cell)
                    for cell in (
                        row["timestamp"].isoformat() if hasattr(row["timestamp"], "isoformat") else row["timestamp"],
                        row["policy_id"],
                        row["policy_version"],
                        row["language_selected"],
                        row["consent_status_general"],
                        "yes" if row["is_active_consent"] else "no",
                        purposes,
                    )
                ]
            )
        fmt = str(ctx.payload.get("format") or "csv").lower()
        if fmt not in {"csv", "pdf"}:
            raise ApiError(400, "Bad Request", "format must be csv or pdf.")
        log_event(
            user_id,
            fid,
            "APP",
            None,
            "CONSENT_HISTORY_EXPORTED",
            {"rows": len(rows), "format": fmt},
            initiator="PRINCIPAL" if ctx.auth_via_principal_jwt else "INTEGRATOR",
            source_ip=ctx.source_ip,
        )
        if fmt == "pdf":
            from dpdpcms_py.kernel.pdfgen import text_pdf

            # UD-04: purposes are named in the language the principal consented
            # in (or `language`, if asked), so the export reads in their language.
            language = ctx.payload.get("language")
            lines = [
                # A principal (or their fiduciary's key) sees the id; a console operator a mask.
                f"Principal: {pii.principal_view(ctx, user_id)}",
                f"Generated: {datetime.now(UTC).isoformat()}",
                f"Records: {len(rows)}",
                "",
            ]
            for row in rows:
                lang = str(language or row["language_selected"] or "en")
                names = _purpose_names(row.get("policy_content"), lang)
                stamp = row["timestamp"].isoformat() if hasattr(row["timestamp"], "isoformat") else row["timestamp"]
                lines += [
                    f"{stamp}  {row['consent_status_general']}  ({'active' if row['is_active_consent'] else 'inactive'})",
                    f"  Policy {row['policy_id']} v{row['policy_version']}, language {row['language_selected']}",
                    "  Purposes:",
                ]
                points = [p for p in row.get("data_point_consents") or [] if isinstance(p, dict)]
                for point in points:
                    pid = point_purpose_id(point)
                    name = names.get(pid)
                    label = f"{name} ({pid})" if name and name != pid else pid
                    lines.append(f"    - {label}: {'granted' if _point_granted(point) else 'withdrawn'}")
                if not points:
                    lines.append("    -")
                lines.append("")
            return text_pdf("Consent history", lines)
        return output.getvalue()
