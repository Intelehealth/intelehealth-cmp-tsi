from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    bind_principal_field,
    canonical_purpose_id,
    point_purpose_id,
    require,
)
from dpdpcms_py.modules.audit_logging.ledger import log_event
from dpdpcms_py.modules.consent_lifecycle.common import (
    _CLIENT_METADATA_SQL,
    _USER_MATCH,
    _fid,
    _notify_principal,
    _observed_metadata,
    _point_granted,
    _raise_consent_alert,
)

NOTIF_WITHDRAWAL_ACK = "WITHDRAWAL_ACKNOWLEDGMENT"


NOTIF_ERASURE_REQUESTED = "ERASURE_REQUESTED_NOTIFICATION"


# Cessation-based retention window stamped on each purpose at withdrawal (Section
# 8(7)). Mirrors the Java build, which recorded a 1095-day expiry per purpose.
RETENTION_CESSATION_DAYS = 1095


def _normalise_purpose_ids(payload: dict) -> list[str]:
    """Collect the purpose selection from 'purpose_ids' (array/string) and the legacy 'purpose_id' alias."""
    raw = payload.get("purpose_ids") or []
    if isinstance(raw, str):
        raw = [raw]
    ids = [canonical_purpose_id(item) for item in raw if item is not None and str(item).strip()]
    single = payload.get("purpose_id")
    if single is not None and str(single).strip() and canonical_purpose_id(single) not in ids:
        ids.append(canonical_purpose_id(single))
    return ids


# P16-01: the shortest free-text reason accepted for a withdrawal an operator
# makes on a principal's behalf when no grievance is linked.
OPERATOR_WITHDRAWAL_REASON_MIN = 10


def _operator_withdrawal_basis(ctx: RequestContext, fid: str) -> dict[str, Any]:
    """P16-01: why a console operator withdrew (or asked erasure of) a principal's consent.

    s.6(4) makes withdrawal the principal's act, so an operator acting for one
    must record the instruction: a grievance of this fiduciary (by its
    reference number), or a written reason. Refused before anything is written.
    """
    reference = str(ctx.payload.get("grievance_reference") or "").strip()
    if reference:
        row = db.one(
            "SELECT id FROM grievances WHERE fiduciary_id = %s AND reference_number = %s LIMIT 1", (fid, reference)
        )
        if not row:
            raise ApiError(400, "Bad Request", "grievance_reference does not name a grievance of this fiduciary.")
        return {"grievance_reference": reference, "grievance_id": str(row["id"])}
    if len(str(ctx.payload.get("reason") or "").strip()) < OPERATOR_WITHDRAWAL_REASON_MIN:
        raise ApiError(
            400,
            "Bad Request",
            "A withdrawal made by a console operator needs a grievance_reference, or a reason of at least "
            f"{OPERATOR_WITHDRAWAL_REASON_MIN} characters recording the principal's instruction.",
        )
    return {}


class WithdrawalHandlers:
    def get_withdrawal_implications(self, ctx: RequestContext) -> dict:
        """CW-04: what withdrawing each consented purpose means, shown before the
        principal confirms — the service impact, and whether the law requires the
        data to be kept anyway."""
        from dpdpcms_py.modules.administration.api import legal_hold_for

        bind_principal_field(ctx, "user_id")
        fid = _fid(ctx)
        user_id = require(ctx.payload.get("user_id"), "user_id")
        language = str(ctx.payload.get("language") or "en")
        where = f"cr.{_USER_MATCH} AND cr.fiduciary_id = %s AND cr.is_active_consent IS TRUE"
        params: list[Any] = [*pii.hmac_params(user_id), fid]
        if ctx.payload.get("policy_id"):
            where += " AND cr.policy_id = %s"
            params.append(ctx.payload["policy_id"])
        # CW-03: one active record per policy; cover every one (newest first).
        records = db.all(
            f"""
            SELECT cr.data_point_consents, p.policy_content
            FROM consent_records cr
            JOIN consent_policies p ON p.id = cr.policy_id AND p.version = cr.policy_version AND p.fiduciary_id = cr.fiduciary_id
            WHERE {where}
            ORDER BY cr.timestamp DESC
            """,
            params,
        )
        if not records:
            raise ApiError(404, "Not Found", "No active consent found.")
        wanted = set(_normalise_purpose_ids(ctx.payload))
        out = []
        seen: set[str] = set()
        granted_points = []
        for record in records:
            content = record.get("policy_content") or {}
            block = content.get(language) or content.get("en") or next(iter(content.values()), {})
            purposes = {
                canonical_purpose_id(p.get("id")): p
                for p in (block.get("data_processing_purposes") or [])
                if isinstance(p, dict)
            }
            for point in record.get("data_point_consents") or []:
                if isinstance(point, dict) and _point_granted(point):
                    granted_points.append((point, purposes))
        for point, purposes in granted_points:
            pid = point_purpose_id(point)
            if (wanted and pid not in wanted) or pid in seen:
                continue
            seen.add(pid)
            purpose = purposes.get(pid, {})
            mandatory = bool(purpose.get("is_mandatory_for_service"))
            hold = legal_hold_for(fid, pid)
            consequence = purpose.get("withdrawal_consequence") or (
                "This purpose is required to provide the service; withdrawing it stops the service that depends on it."
                if mandatory
                else "Processing for this purpose stops. Other purposes and the service are not affected."
            )
            out.append(
                {
                    "purpose_id": pid,
                    "name": purpose.get("name") or pid,
                    "is_mandatory_for_service": mandatory,
                    "consequence": consequence,
                    "data_retained_by_law": bool(hold),
                    "legal_reference": hold["legal_reference"] if hold else None,
                    "retention_days": hold["days"] if hold else None,
                }
            )
        return {"success": True, "language": language, "purposes": out}

    def withdraw_consent(self, ctx: RequestContext) -> dict:
        return self._withdraw(ctx, erasure=False)

    def erasure_request(self, ctx: RequestContext) -> dict:
        return self._withdraw(ctx, erasure=True)

    def _withdraw(self, ctx: RequestContext, erasure: bool) -> dict:
        bind_principal_field(ctx, "user_id")
        fid = _fid(ctx)
        user_id = require(ctx.payload.get("user_id"), "user_id")
        purpose_ids = _normalise_purpose_ids(ctx.payload)
        operator_basis = _operator_withdrawal_basis(ctx, fid) if ctx.operator_id else None
        status = "ERASURE_REQUESTED" if erasure else "WITHDRAWN"
        expiry = (datetime.now(UTC) + timedelta(days=RETENTION_CESSATION_DAYS)).isoformat()
        record_id = None
        held: list[dict] = []
        purge_requests: list[dict] = []
        with db.connection() as conn, conn.cursor() as cur:
            # Legal-hold race: serialise with _set_purge_status for this
            # principal, so a purge being confirmed either sees the hold rows
            # written below or completes before they are. Taken FIRST, before any
            # consent_records row lock, and for plain withdrawals too: the purge
            # path rewrites the same consent_records rows, so both sides take the
            # advisory lock before any row lock and cannot deadlock.
            from dpdpcms_py.modules.consent_lifecycle.erasure import lock_principal_purges

            lock_principal_purges(cur, fid, pii.normalize(str(user_id)))
            # CW-03: one active record per policy. Withdraw from every active record
            # (optionally only the named policy's) that holds a named purpose.
            policy_filter = ctx.payload.get("policy_id")
            cur.execute(
                f"SELECT * FROM consent_records WHERE {_USER_MATCH} AND fiduciary_id = %s AND is_active_consent IS TRUE"
                + (" AND policy_id = %s" if policy_filter else "")
                + " ORDER BY timestamp DESC FOR UPDATE",
                (*pii.hmac_params(user_id), fid, *([policy_filter] if policy_filter else [])),
            )
            active_rows = cur.fetchall()
            # P9-07 / CW-06: with no active consent there is nothing to withdraw.
            # Succeeding here fired the acknowledgement, webhook, alert and audit
            # cascade for a withdrawal that never happened. An erasure request
            # stays valid after consent was already withdrawn (s.12 right).
            if not active_rows and not erasure:
                raise ApiError(404, "Not Found", "No active consent found to withdraw.")
            if active_rows and purpose_ids:
                # CW-06: every purpose named for withdrawal must currently hold an
                # active grant; withdrawing something that was never granted is an
                # error an integrator can act on, not a silent success.
                granted = {
                    point_purpose_id(p)
                    for active in active_rows
                    for p in active["data_point_consents"] or []
                    if isinstance(p, dict) and _point_granted(p)
                }
                missing = [pid for pid in purpose_ids if pid not in granted]
                if missing:
                    raise ApiError(
                        400,
                        "Bad Request",
                        f"Purpose(s) {sorted(missing)} do not have active consent and cannot be withdrawn.",
                    )
            record_ids: list[str] = []
            for row in active_rows:
                points = row["data_point_consents"] or []
                if purpose_ids and not any(
                    isinstance(p, dict) and _point_granted(p) and point_purpose_id(p) in set(purpose_ids)
                    for p in points
                ):
                    continue  # this policy's record holds none of the named purposes
                full_withdrawal = not purpose_ids
                updated: list[Any] = []
                for point in points:
                    if not isinstance(point, dict):
                        updated.append(point)
                        continue
                    matches = full_withdrawal or point_purpose_id(point) in purpose_ids
                    if matches:
                        point = dict(point)
                        point["consent_granted"] = False
                        point["consent_expiry"] = expiry
                        point["status"] = "withdrawn"
                    updated.append(point)
                remaining = [p for p in updated if isinstance(p, dict) and _point_granted(p)]
                is_active = bool(remaining)
                row_status = status if not remaining else "PARTIAL_WITHDRAWAL"
                # CC-07/CW-07: append, never overwrite. The prior record keeps its
                # purposes exactly as granted and is only retired from "active";
                # the withdrawal is a new record that points back at it.
                observed = _observed_metadata(ctx)
                cur.execute(
                    "UPDATE consent_records SET is_active_consent = FALSE, last_updated_at = NOW() WHERE id = %s",
                    (row["id"],),
                )
                cur.execute(
                    f"""
                    INSERT INTO consent_records
                        (id, user_id_enc, user_id_hmac, fiduciary_id, policy_id, policy_version, timestamp,
                         jurisdiction, language_selected, consent_status_general, consent_mechanism,
                         ip_address_enc, user_agent, data_point_consents, is_active_consent,
                         verification_log_id, session_id, session_source, client_metadata,
                         supersedes_record_id, created_at, last_updated_at)
                    VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, NOW(), %s, %s, %s, %s,
                            {db.enc_expr()}, %s, %s, %s, %s, %s, %s, {_CLIENT_METADATA_SQL}, %s, NOW(), NOW())
                    RETURNING id
                    """,
                    (
                        row["user_id_enc"],
                        row["user_id_hmac"],
                        row["fiduciary_id"],
                        row["policy_id"],
                        row["policy_version"],
                        row["jurisdiction"],
                        row["language_selected"],
                        row_status,
                        observed["mechanism"],
                        *db.bind_encrypt(observed["ip_address"]),
                        observed["user_agent"],
                        db.as_jsonb(updated),
                        is_active,
                        row.get("verification_log_id"),
                        observed["session_id"],
                        observed["session_source"],
                        db.as_jsonb(observed["client_metadata"]),
                        *db.bind_encrypt(observed["claimed_ip_address"]),
                        row["id"],
                    ),
                )
                record_ids.append(str(cur.fetchone()["id"]))
            record_id = record_ids[0] if record_ids else None
            if erasure:
                from dpdpcms_py.modules.administration.api import legal_hold_for

                # SEC-04: an erasure filed through an integrator key is bound to a
                # REAL principal. Without this, a WRITE+PURGE key could call
                # erasure_request with any user_id in the tenant — no active
                # consent on file — create a purge row stamped with its own
                # app_id, and then confirm it, reaching erase_cms_copy with no
                # relationship to the subject at all. Require an actual consent
                # record before a key may open an erasure on a principal.
                if ctx.permissions and not ctx.auth_via_principal_jwt:
                    exists = db.one(
                        f"SELECT 1 FROM consent_records WHERE {_USER_MATCH} AND fiduciary_id = %s LIMIT 1",
                        (*pii.hmac_params(user_id), fid),
                    )
                    if not exists:
                        raise ApiError(
                            403,
                            "Forbidden",
                            "This principal has no consent record with this fiduciary; an erasure request must reference a principal the fiduciary actually holds data on.",
                        )

                targets = purpose_ids or ["ALL"]
                # SEC-04: an erasure initiated through an integrator key records
                # which app opened it, so only that processor can later confirm
                # the purge (confirm_purge_status binds to the key's app).
                initiator_app_id = ctx.app_id if ctx.permissions else None
                for target in targets:
                    # CW-11: decide at withdrawal time whether the law requires the
                    # data to be kept; a held request says so and cites the rule.
                    hold = legal_hold_for(fid, target)
                    cur.execute(
                        f"""
                        INSERT INTO purge_requests
                            (user_id_enc, user_id_hmac, fiduciary_id, purpose_id, trigger_event, details, status,
                             legal_reference, hold_until, app_id)
                        VALUES ({pii.ENC_SQL}, {pii.HMAC_SQL}, %s, %s, 'ErasureRequest', %s, %s, %s,
                                CASE WHEN %s::int IS NULL THEN NULL ELSE NOW() + make_interval(days => %s::int) END, %s)
                        RETURNING id, status, hold_until
                        """,
                        (
                            *pii.enc_params(user_id),
                            *pii.hmac_params(user_id),
                            fid,
                            target,
                            ctx.payload.get("reason"),
                            "LEGAL_HOLD_APPLIED" if hold else "PENDING",
                            hold["legal_reference"] if hold else None,
                            hold["days"] if hold else None,
                            hold["days"] if hold else None,
                            initiator_app_id,
                        ),
                    )
                    # The principal gets a handle on each request opened in their name.
                    purge = cur.fetchone() or {}
                    hold_until = purge.get("hold_until")
                    purge_requests.append(
                        {
                            "purge_request_id": str(purge["id"]) if purge.get("id") is not None else None,
                            "purpose_id": target,
                            "status": purge.get("status"),
                            "legal_reference": hold["legal_reference"] if hold else None,
                            "hold_until": hold_until.isoformat() if hasattr(hold_until, "isoformat") else hold_until,
                        }
                    )
                    if hold:
                        held.append(
                            {
                                "purpose_id": target,
                                "legal_reference": hold["legal_reference"],
                                "hold_until": purge_requests[-1]["hold_until"],
                            }
                        )
        _notify_principal(user_id, fid, NOTIF_ERASURE_REQUESTED if erasure else NOTIF_WITHDRAWAL_ACK)
        details: dict[str, Any] = {
            "reason": ctx.payload.get("reason"),
            "purpose_ids": purpose_ids,
            "record_id": record_id,
        }
        if operator_basis is not None:
            details.update(operator_basis)
        log_event(
            user_id,
            fid,
            # P16-01: a console operator's withdrawal is attributed to that
            # operator, as a grievance the operator logs already is.
            "DPO_CONSOLE" if ctx.operator_id else "APP",
            None,
            "ERASURE_REQUESTED" if erasure else "CONSENT_WITHDRAWN",
            details,
            purpose_id=purpose_ids[0] if purpose_ids and len(purpose_ids) == 1 else None,
            consent_status=status,
            initiator=(
                f"OPERATOR:{ctx.operator_id}"
                if ctx.operator_id
                else "PRINCIPAL"
                if ctx.auth_via_principal_jwt
                else "INTEGRATOR"
            ),
            source_ip=ctx.source_ip,
        )
        # CW-08: push a stop signal to linked systems instead of relying on them
        # to poll. Delivery happens through the webhook dispatcher worker.
        try:
            from dpdpcms_py.modules.notifications.api import queue_webhook

            queue_webhook(
                fid,
                "ERASURE_REQUESTED" if erasure else "CONSENT_WITHDRAWN",
                {"user_id": user_id, "purpose_ids": purpose_ids, "consent_record_id": record_id, "erasure": erasure},
            )
        except Exception:  # pragma: no cover
            pass
        # NT-07: withdrawal is the BRD's headline alert event — raise it as an
        # alert the fiduciary must acknowledge, not only a webhook.
        _raise_consent_alert(
            fid,
            "ERASURE_REQUESTED" if erasure else "CONSENT_WITHDRAWN",
            record_id,
            {"user_id": user_id, "purpose_ids": purpose_ids, "legal_holds": held},
        )
        # CW-08: every linked processor is told too, on its own endpoint, and
        # must acknowledge its own alert.
        try:
            from dpdpcms_py.modules.notifications.api import notify_processors

            processors = notify_processors(
                fid,
                "ERASURE_REQUESTED" if erasure else "CONSENT_WITHDRAWN",
                record_id,
                {"user_id": user_id, "purpose_ids": purpose_ids, "consent_record_id": record_id, "erasure": erasure},
                category="PURGE" if erasure else "NOTIFICATION",
            )
        except Exception:  # pragma: no cover - a fan-out failure never undoes the withdrawal
            processors = []
        out = {
            "success": True,
            "message": "Erasure request submitted." if erasure else "Consent withdrawn successfully.",
            "consent_record_id": record_id,
            "consent_record_ids": record_ids,
            "processors_notified": len(processors),
        }
        if purge_requests:
            out["purge_requests"] = purge_requests
        if held:
            out["retained_under_legal_hold"] = held
        return out
