from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from .. import db, principal_otp
from ..audit import log_event
from ..context import RequestContext
from ..errors import ApiError
from ..security import principal_token
from .base import Service, bind_principal_field, ensure_principal_owns, page_limit, reject_principal, require
from .catalog import resolve_fiduciary


def _fid(ctx: RequestContext) -> str:
    return require(resolve_fiduciary(ctx), "fiduciary_id")


def _consent_row(row: dict | None) -> dict | None:
    return db.to_jsonable(row) if row else None


NOTIF_CONSENT_GIVEN = "CONSENT_GIVEN_NOTIFICATION"
NOTIF_WITHDRAWAL_ACK = "WITHDRAWAL_ACKNOWLEDGMENT"
NOTIF_ERASURE_REQUESTED = "ERASURE_REQUESTED_NOTIFICATION"
NOTIF_VALIDATION_DENIED = "CONSENT_VALIDATION_DENIED"

# CC-05: how a guardian's identity may be established. Only EXISTING_ACCOUNT and
# DIGILOCKER can reach VERIFIED; the rest are recorded as assertions.
GUARDIAN_MECHANISMS = {"EXISTING_ACCOUNT", "DIGILOCKER", "AADHAAR_VC", "KYC_PROVIDER", "OTP_LINKING"}

# Cessation-based retention window stamped on each purpose at withdrawal (Section
# 8(7)). Mirrors the Java build, which recorded a 1095-day expiry per purpose.
RETENTION_CESSATION_DAYS = 1095


def _purpose_names(policy_content: Any, language: str) -> dict[str, str]:
    """purpose id (lower-case) -> name, from the policy block for `language`,
    falling back to English and then to whichever block the policy has."""
    if not isinstance(policy_content, dict) or not policy_content:
        return {}
    block = policy_content.get(language) or policy_content.get("en") or next(iter(policy_content.values()))
    if not isinstance(block, dict):
        return {}
    return {
        str(p.get("id")).lower(): str(p["name"])
        for p in block.get("data_processing_purposes") or []
        if isinstance(p, dict) and p.get("id") and p.get("name")
    }


def _point_granted(point: dict) -> bool:
    """Data points are stored as {data_point_id, consent_granted, consent_expiry}; an expired
    grant no longer counts. 'status' is accepted as an older alias for consent_granted."""
    granted = point.get("consent_granted")
    if granted is None:
        granted = str(point.get("status", "")).lower() in {"granted", "true", "consent_given"}
    if not granted:
        return False
    expiry = point.get("consent_expiry")
    if expiry:
        try:
            if datetime.fromisoformat(str(expiry).replace("Z", "+00:00")) <= datetime.now(UTC):
                return False
        except ValueError:
            pass
    return True


def _point_grants(point: dict, purpose_id: str) -> bool:
    """As above, for one specific purpose. 'id'/'purpose_id' are older aliases for data_point_id."""
    stored_id = point.get("data_point_id") or point.get("id") or point.get("purpose_id")
    if not stored_id or str(stored_id).lower() != purpose_id.lower():
        return False
    return _point_granted(point)


def _normalise_purpose_ids(payload: dict) -> list[str]:
    """Collect the purpose selection from 'purpose_ids' (array/string) and the legacy 'purpose_id' alias."""
    raw = payload.get("purpose_ids") or []
    if isinstance(raw, str):
        raw = [raw]
    ids = [str(item).strip() for item in raw if item is not None and str(item).strip()]
    single = payload.get("purpose_id")
    if single is not None and str(single).strip() and str(single).strip() not in ids:
        ids.append(str(single).strip())
    return ids


def declared_purpose_ids(policy_content: dict | None) -> set[str]:
    """Purpose IDs declared across every language block of a policy."""
    if not isinstance(policy_content, dict):
        return set()
    ids: set[str] = set()
    for block in policy_content.values():
        if not isinstance(block, dict):
            continue
        for purpose in block.get("data_processing_purposes") or []:
            if isinstance(purpose, dict) and purpose.get("id"):
                ids.add(str(purpose["id"]))
    return ids


def check_consent_alignment(fiduciary_id: str, policy_id: str, version: str, data_consents: list[Any]) -> set[str]:
    """CU-05: every purpose in a consent submission must be declared by the policy,
    and no CLOSED purpose (PL-02/03) may be granted. Returns the closed purpose ids
    (lower-case) so the explicit-choice check does not demand a decision on them."""
    policy = db.one(
        "SELECT policy_content FROM consent_policies WHERE id = %s AND version = %s AND fiduciary_id = %s",
        (policy_id, version, fiduciary_id),
    )
    if not policy:
        raise ApiError(404, "Not Found", f"Policy {policy_id} version {version} not found.")
    declared = declared_purpose_ids(policy.get("policy_content"))

    requested: set[str] = set()
    granted: set[str] = set()
    if isinstance(data_consents, list):
        for point in data_consents:
            if not isinstance(point, dict):
                continue
            pid = point.get("data_point_id") or point.get("purpose_id") or point.get("id")
            if pid:
                requested.add(str(pid).lower())
                if point.get("consent_granted") is True:
                    granted.add(str(pid).lower())
    for pid in requested:
        if pid not in {d.lower() for d in declared}:
            raise ApiError(
                400,
                "Bad Request",
                f"Purpose '{pid}' is not declared in policy {policy_id} version {version}.",
            )

    closed = db.all(
        "SELECT purpose_id FROM purpose_lifecycle WHERE fiduciary_id = %s AND state = 'CLOSED'",
        (fiduciary_id,),
    )
    closed_ids = {str(row["purpose_id"]).lower() for row in closed}
    # PL-02: a closed purpose may still be declared by the policy until a new
    # version drops it. Declining it (or leaving it out) is fine; granting it is not.
    overlap = granted & closed_ids
    if overlap:
        raise ApiError(
            403,
            "Forbidden",
            f"Purpose(s) {sorted(overlap)} are closed — consent cannot be granted for a closed purpose.",
        )
    return closed_ids


def check_explicit_choices(policy_content: dict | None, data_consents: Any, closed: set[str] | None = None) -> None:
    """CC-03: consent must be granular and affirmative, never bundled or implied.

    Every purpose the policy declares needs its own explicit yes/no in the
    submission (an omitted purpose would otherwise read as a silent default),
    each decision must be a real boolean, and no purpose may appear twice.
    A CLOSED purpose (PL-02) needs no decision: it can no longer be granted.
    """
    if not isinstance(data_consents, list) or not data_consents:
        raise ApiError(400, "Bad Request", "data_point_consents must list a decision for each purpose.")
    seen: set[str] = set()
    for point in data_consents:
        if not isinstance(point, dict):
            raise ApiError(400, "Bad Request", "data_point_consents entries must be objects.")
        pid = str(point.get("data_point_id") or point.get("purpose_id") or point.get("id") or "").lower()
        if not pid:
            raise ApiError(400, "Bad Request", "Each consent decision must name its data_point_id.")
        if pid in seen:
            raise ApiError(400, "Bad Request", f"Purpose '{pid}' appears more than once.")
        seen.add(pid)
        if not isinstance(point.get("consent_granted"), bool):
            raise ApiError(
                400,
                "Bad Request",
                f"Purpose '{pid}' needs an explicit consent_granted true/false; consent is never implied (CC-03).",
            )
    exempt = seen | (closed or set())
    undecided = sorted(d for d in {d.lower() for d in declared_purpose_ids(policy_content)} if d not in exempt)
    if undecided:
        raise ApiError(
            400,
            "Bad Request",
            f"No explicit decision for purpose(s) {undecided}; every purpose must be accepted or declined individually.",
        )


def observed_mechanism(ctx: RequestContext) -> str:
    """CC-04/CC-06: how the consent reached the CMS, as the server saw it, never as the caller claims."""
    if ctx.auth_via_principal_jwt:
        return "PRINCIPAL_PORTAL"
    if ctx.category == "admin":
        return "ADMIN_CONSOLE"
    return "INTEGRATOR_API"


def _observed_metadata(ctx: RequestContext) -> dict[str, Any]:
    """Server-observed capture metadata, plus whatever the caller claimed, kept apart."""
    payload = ctx.payload
    session_id = ctx.session_id or payload.get("session_id")
    return {
        "mechanism": observed_mechanism(ctx),
        "ip_address": ctx.source_ip or "0.0.0.0",
        "user_agent": ctx.headers.get("user-agent") or ctx.headers.get("User-Agent"),
        "session_id": session_id,
        # A principal session id comes from the CMS's own token; an integrator's is its claim.
        "session_source": "CMS" if ctx.session_id else ("CLIENT" if session_id else None),
        "client_metadata": {
            key: payload[key]
            for key in ("consent_mechanism", "ip_address", "user_agent", "session_id")
            if payload.get(key) is not None
        },
    }


def _verify_with_digilocker(fiduciary_id: str, guardian_id: str, ref_id: str) -> tuple[str, str | None]:
    """Confirm a DigiLocker reference through the configured verifier service.

    The verifier is the deployment's DigiLocker partner integration. It receives
    the reference and answers {"verified": bool, "is_adult": bool}. With no
    verifier configured the log stays PENDING and cannot back a minor's consent.
    """
    import json

    from ..config import settings
    from ..netutil import post_json

    if not settings.digilocker_verify_url:
        return "PENDING", "No DigiLocker verifier is configured (DIGILOCKER_VERIFY_URL)."
    try:
        status, body = post_json(
            settings.digilocker_verify_url,
            {"fiduciary_id": fiduciary_id, "guardian_principal_id": guardian_id, "verification_ref_id": ref_id},
            timeout=15,
        )
    except ValueError as exc:
        return "PENDING", str(exc)
    if status is None or status >= 400:
        return "PENDING", f"DigiLocker verifier unavailable ({status})."
    try:
        answer = json.loads(body or "{}")
    except ValueError:
        return "PENDING", "DigiLocker verifier returned an unreadable response."
    if answer.get("verified") is True and answer.get("is_adult") is True:
        return "VERIFIED", None
    return "REJECTED", "DigiLocker did not confirm an adult guardian for this reference."


def _raise_consent_alert(fiduciary_id: str, alert_type: str, record_id: str | None, payload: dict) -> None:
    """NT-07: an alert row (acknowledgeable, escalated by the worker) plus its dispatch."""
    try:
        from .alerts import enqueue_alert_dispatch
        from .lifecycle import record_alert

        enqueue_alert_dispatch(fiduciary_id, record_alert(fiduciary_id, alert_type, record_id, payload))
    except Exception:  # pragma: no cover - an alert failure never undoes the consent action
        pass


def _notify_principal(user_id: str, fiduciary_id: str, notification_type: str) -> None:
    db.execute(
        "INSERT INTO notifications (recipient_type, recipient_id, fiduciary_id, notification_type) VALUES ('PRINCIPAL', %s, %s, %s)",
        (user_id, fiduciary_id, notification_type),
    )


class ConsentService(Service):
    def record_consent(self, ctx: RequestContext) -> dict:
        payload = ctx.payload
        bind_principal_field(ctx, "user_id")
        fid = _fid(ctx)
        user_id = require(payload.get("user_id"), "user_id")
        policy_id = require(payload.get("policy_id"), "policy_id")
        data_consents = require(payload.get("data_point_consents"), "data_point_consents")
        requested_version = payload.get("version") or payload.get("policy_version") or ""
        if requested_version:
            policy = db.one(
                "SELECT version, policy_content FROM consent_policies WHERE id = %s AND version = %s AND fiduciary_id = %s",
                (policy_id, requested_version, fid),
            )
            if not policy:
                raise ApiError(
                    400, "Bad Request", f"Policy version mismatch: no version '{requested_version}' for {policy_id}."
                )
            version = requested_version
        else:
            # Notice versioning: when the client does not state which notice the
            # principal agreed to, stamp the current (preferring ACTIVE) version so
            # the consent record always identifies the notice it points at.
            policy = db.one(
                "SELECT version, policy_content FROM consent_policies WHERE id = %s AND fiduciary_id = %s ORDER BY (status = 'ACTIVE') DESC, effective_date DESC LIMIT 1",
                (policy_id, fid),
            )
            if not policy:
                raise ApiError(400, "Bad Request", f"Policy not found: {policy_id}.")
            version = policy["version"]
        # CU-05: the submission may only reference purposes the policy declares,
        # and never grant a purpose that is CLOSED under the purpose lifecycle.
        closed = check_consent_alignment(fid, policy_id, version, data_consents)
        check_explicit_choices(policy.get("policy_content"), data_consents, closed)
        age_category = str(payload.get("age_category") or "ADULT").upper()
        guardian_id = payload.get("guardian_id")
        verification_log_id = payload.get("verification_log_id")
        if age_category == "MINOR":
            # CC-05: a minor's consent always rests on a VERIFIED guardian log;
            # naming a guardian_id alone is an assertion, not a verification.
            where = "child_principal_id = %s AND fiduciary_id = %s AND verification_status = 'VERIFIED'"
            params: list[Any] = [user_id, fid]
            if guardian_id:
                where += " AND guardian_principal_id = %s"
                params.append(guardian_id)
            if verification_log_id:
                where += " AND id = %s"
                params.append(verification_log_id)
            parent_log = db.one(
                f"SELECT id, guardian_principal_id FROM parental_verification_logs WHERE {where} ORDER BY verified_at DESC LIMIT 1",
                params,
            )
            if not parent_log:
                raise ApiError(
                    403, "Forbidden", "A verified guardian consent is required to record consent for a minor."
                )
            verification_log_id = str(parent_log["id"])
            guardian_id = guardian_id or parent_log["guardian_principal_id"]
        observed = _observed_metadata(ctx)
        with db.connection() as conn, conn.cursor() as cur:
            cur.execute(
                # CW-03/UD-05: a principal holds one active record per policy. Recording
                # consent under one policy must not retire their consent under another.
                "UPDATE consent_records SET is_active_consent = FALSE, last_updated_at = NOW() WHERE user_id = %s AND fiduciary_id = %s AND policy_id = %s AND is_active_consent IS TRUE RETURNING id",
                (user_id, fid, policy_id),
            )
            prior = cur.fetchone()
            cur.execute(
                """
                INSERT INTO consent_records
                    (id, user_id, fiduciary_id, policy_id, policy_version, timestamp,
                     jurisdiction, language_selected, consent_status_general, consent_mechanism,
                     ip_address, user_agent, data_point_consents, is_active_consent,
                     verification_log_id, session_id, session_source, client_metadata,
                     supersedes_record_id, created_at, last_updated_at)
                VALUES (uuid_generate_v4(), %s, %s, %s, %s, NOW(), %s, %s, %s, %s,
                        %s, %s, %s, TRUE, %s, %s, %s, %s, %s, NOW(), NOW())
                RETURNING id
                """,
                (
                    user_id,
                    fid,
                    policy_id,
                    version,
                    payload.get("jurisdiction", "IN"),
                    payload.get("language_selected", "en"),
                    "CONSENT_GIVEN",
                    observed["mechanism"],
                    observed["ip_address"],
                    observed["user_agent"],
                    db.as_jsonb(data_consents),
                    verification_log_id,
                    observed["session_id"],
                    observed["session_source"],
                    db.as_jsonb(observed["client_metadata"]),
                    prior["id"] if prior else None,
                ),
            )
            cid = str(cur.fetchone()["id"])
            cur.execute(
                """
                INSERT INTO data_principal (user_id, fiduciary_id, last_consent_mechanism, age_category, guardian_id, verification_status)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (user_id, fiduciary_id) DO UPDATE SET
                    last_consent_mechanism = EXCLUDED.last_consent_mechanism,
                    age_category = EXCLUDED.age_category,
                    guardian_id = EXCLUDED.guardian_id,
                    verification_status = EXCLUDED.verification_status
                """,
                (
                    user_id,
                    fid,
                    observed["mechanism"],
                    age_category,
                    guardian_id,
                    "GUARDIAN_VERIFIED" if age_category == "MINOR" else "NOT_VERIFIED",
                ),
            )
        _notify_principal(user_id, fid, NOTIF_CONSENT_GIVEN)
        grant_purpose_ids = []
        if isinstance(data_consents, list):
            for point in data_consents:
                if isinstance(point, dict) and _point_granted(point):
                    pid = point.get("data_point_id") or point.get("purpose_id") or point.get("id")
                    if pid:
                        grant_purpose_ids.append(str(pid))
        log_event(
            user_id,
            fid,
            "APP",
            None,
            "CONSENT_GIVEN",
            {"policy_id": policy_id, "record_id": cid},
            purpose_id=grant_purpose_ids[0] if len(grant_purpose_ids) == 1 else None,
            consent_status="CONSENT_GIVEN",
            initiator="PRINCIPAL" if ctx.auth_via_principal_jwt else "INTEGRATOR",
            source_ip=ctx.source_ip,
        )
        try:
            from ..webhooks import queue_webhook

            queue_webhook(
                fid,
                "CONSENT_RECORDED",
                {"user_id": user_id, "policy_id": policy_id, "version": version, "consent_record_id": cid},
            )
        except Exception:  # pragma: no cover
            pass
        # NT-07: new and updated consents raise an acknowledgeable alert.
        _raise_consent_alert(
            fid,
            "CONSENT_UPDATED" if prior else "CONSENT_GIVEN",
            cid,
            {"user_id": user_id, "policy_id": policy_id, "version": version, "granted_purposes": grant_purpose_ids},
        )
        return {"success": True, "data": {"consent_record_id": cid, "message": "Consent recorded successfully."}}

    def record_parent_consent(self, ctx: RequestContext) -> dict:
        """CC-05: record a guardian verification, verifying it where the CMS can.

        EXISTING_ACCOUNT is verified here: the guardian must already be a known
        ADULT principal of this fiduciary. DIGILOCKER is verified by the
        configured verifier (DIGILOCKER_VERIFY_URL), which must confirm the
        reference and that the guardian is an adult. Anything else is stored as
        an unverified assertion and cannot back a minor's consent.
        """
        payload = ctx.payload
        bind_principal_field(ctx, "guardian_principal_id")
        fid = _fid(ctx)
        child = require(payload.get("child_principal_id"), "child_principal_id")
        guardian = require(payload.get("guardian_principal_id"), "guardian_principal_id")
        mechanism = str(require(payload.get("verification_mechanism"), "verification_mechanism")).upper()
        if mechanism not in GUARDIAN_MECHANISMS:
            raise ApiError(400, "Bad Request", f"verification_mechanism must be one of {sorted(GUARDIAN_MECHANISMS)}.")
        if guardian == child:
            raise ApiError(400, "Bad Request", "A principal cannot act as their own guardian.")
        ref_id = payload.get("verification_ref_id")
        status, detail = "ASSERTED", "Recorded as an assertion; only EXISTING_ACCOUNT or DIGILOCKER can verify."
        if mechanism == "EXISTING_ACCOUNT":
            adult = db.one(
                "SELECT 1 FROM data_principal WHERE user_id = %s AND fiduciary_id = %s AND COALESCE(age_category, 'ADULT') = 'ADULT'",
                (guardian, fid),
            )
            status = "VERIFIED" if adult else "REJECTED"
            detail = None if adult else "Guardian has no adult account with this fiduciary."
        elif mechanism == "DIGILOCKER":
            require(ref_id, "verification_ref_id")
            status, detail = _verify_with_digilocker(fid, guardian, str(ref_id))
        row = db.insert_returning(
            """
            INSERT INTO parental_verification_logs
                (id, child_principal_id, guardian_principal_id, verification_mechanism,
                 provider_name, verification_ref_id, proof_metadata, fiduciary_id, verification_status)
            VALUES (uuid_generate_v4(), %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                child,
                guardian,
                mechanism,
                payload.get("provider_name") or ("DigiLocker" if mechanism == "DIGILOCKER" else None),
                ref_id,
                db.as_jsonb({**(payload.get("proof_metadata") or {}), "verification_detail": detail}),
                fid,
                status,
            ),
        )
        log_event(
            guardian,
            fid,
            "APP",
            None,
            "GUARDIAN_VERIFICATION_RECORDED",
            {"child_principal_id": child, "mechanism": mechanism, "status": status},
            initiator="PRINCIPAL" if ctx.auth_via_principal_jwt else "INTEGRATOR",
            source_ip=ctx.source_ip,
        )
        return {
            "success": True,
            "verification_log_id": str(row["id"]),
            "verification_status": status,
            "detail": detail,
        }

    def get_active_consent(self, ctx: RequestContext) -> dict:
        bind_principal_field(ctx, "user_id")
        where = ["user_id = %s", "fiduciary_id = %s", "is_active_consent IS TRUE"]
        params: list[Any] = [require(ctx.payload.get("user_id"), "user_id"), _fid(ctx)]
        if ctx.payload.get("policy_id"):
            where.append("policy_id = %s")
            params.append(ctx.payload["policy_id"])
        row = db.one(
            f"SELECT * FROM consent_records WHERE {' AND '.join(where)} ORDER BY timestamp DESC LIMIT 1", params
        )
        if not row:
            raise ApiError(404, "Not Found", "No active consent found.")
        return _consent_row(row)

    def get_consent_record_details(self, ctx: RequestContext) -> dict:
        where = ["id = %s"]
        params: list[Any] = [require(ctx.payload.get("record_id"), "record_id")]
        if ctx.fiduciary_id:
            where.append("fiduciary_id = %s")
            params.append(ctx.fiduciary_id)
        row = db.one(f"SELECT * FROM consent_records WHERE {' AND '.join(where)}", params)
        if not row:
            raise ApiError(404, "Not Found", "Consent record not found.")
        ensure_principal_owns(ctx, row.get("user_id"), label="Consent record")
        return _consent_row(row)

    def list_consent_history(self, ctx: RequestContext) -> list[dict]:
        bind_principal_field(ctx, "user_id")
        payload = ctx.payload
        page, limit = page_limit(payload)
        where = ["user_id = %s", "fiduciary_id = %s"]
        params: list[Any] = [require(payload.get("user_id"), "user_id"), _fid(ctx)]
        # UD-03: search and filter by purpose, date and status.
        if payload.get("purpose_id"):
            where.append(
                "EXISTS (SELECT 1 FROM jsonb_array_elements(data_point_consents) p "
                "WHERE lower(COALESCE(p->>'data_point_id', p->>'purpose_id', p->>'id')) = lower(%s))"
            )
            params.append(str(payload["purpose_id"]))
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
            f"SELECT * FROM consent_records WHERE {' AND '.join(where)} ORDER BY timestamp DESC LIMIT %s OFFSET %s",
            [*params, limit, (page - 1) * limit],
        )
        out = db.to_jsonable(rows)
        # The wallet sync token is a principal credential: only the principal's own
        # session receives it, never an integrator or console reading the history.
        if ctx.auth_via_principal_jwt:
            for item in out:
                item["sync_token"] = principal_token(str(item["fiduciary_id"]), item["user_id"])
        return out

    def list_consents(self, ctx: RequestContext) -> dict:
        """Cross-principal consent listing for the DPO console. Always scoped to one fiduciary."""
        payload = ctx.payload
        page, limit = page_limit(payload, 25)
        where = ["fiduciary_id = %s"]
        params: list[Any] = [_fid(ctx)]
        if payload.get("user_id"):
            where.append("user_id ILIKE %s")
            params.append(f"%{payload['user_id']}%")
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
            SELECT id AS record_id, user_id, policy_id, policy_version, consent_status_general,
                   is_active_consent, timestamp, language_selected, consent_mechanism,
                   jurisdiction, data_point_consents
            FROM consent_records WHERE {clause}
            ORDER BY timestamp DESC LIMIT %s OFFSET %s
            """,
            [*params, limit, (page - 1) * limit],
        )
        out = []
        for row in db.to_jsonable(rows):
            points = row.pop("data_point_consents", None) or []
            points = [p for p in points if isinstance(p, dict)]
            row["purposes_total"] = len(points)
            row["purposes_granted"] = sum(1 for p in points if _point_granted(p))
            out.append(row)
        return {"success": True, "data": out, "page": page, "limit": limit, "total": total["count"] if total else 0}

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
            """
            SELECT cr.timestamp, cr.policy_id, cr.policy_version, cr.language_selected,
                   cr.consent_status_general, cr.is_active_consent, cr.data_point_consents,
                   p.policy_content
            FROM consent_records cr
            LEFT JOIN consent_policies p
                   ON p.id = cr.policy_id AND p.version = cr.policy_version AND p.fiduciary_id = cr.fiduciary_id
            WHERE cr.user_id = %s AND cr.fiduciary_id = %s
            ORDER BY cr.timestamp DESC
            """,
            (user_id, fid),
        )
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["timestamp", "policy_id", "policy_version", "language", "status", "active", "purposes"])
        for row in rows:
            points = row.get("data_point_consents") or []
            purposes = ", ".join(
                str(p.get("data_point_id") or p.get("id") or "")
                + ("" if _point_granted(p) else ":withdrawn")
                for p in points
                if isinstance(p, dict)
            )
            writer.writerow(
                [
                    row["timestamp"].isoformat() if hasattr(row["timestamp"], "isoformat") else row["timestamp"],
                    row["policy_id"],
                    row["policy_version"],
                    row["language_selected"],
                    row["consent_status_general"],
                    "yes" if row["is_active_consent"] else "no",
                    purposes,
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
            from ..pdfgen import text_pdf

            # UD-04: purposes are named in the language the principal consented
            # in (or `language`, if asked), so the export reads in their language.
            language = ctx.payload.get("language")
            lines = [f"Principal: {user_id}", f"Generated: {datetime.now(UTC).isoformat()}", f"Records: {len(rows)}", ""]
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
                    pid = str(point.get("data_point_id") or point.get("id") or "")
                    name = names.get(pid.lower())
                    label = f"{name} ({pid})" if name and name != pid else pid
                    lines.append(f"    - {label}: {'granted' if _point_granted(point) else 'withdrawn'}")
                if not points:
                    lines.append("    -")
                lines.append("")
            return text_pdf("Consent history", lines)
        return output.getvalue()

    def list_principals(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(
            db.all(
                "SELECT * FROM data_principal WHERE fiduciary_id = %s ORDER BY created_at DESC LIMIT %s",
                (_fid(ctx), int(ctx.payload.get("limit") or 20)),
            )
        )

    def link_user(self, ctx: RequestContext) -> dict:
        reject_principal(ctx, "Linking anonymous sessions requires an application API key.")
        anon = require(ctx.payload.get("anonymous_user_id"), "anonymous_user_id")
        auth = require(ctx.payload.get("authenticated_user_id"), "authenticated_user_id")
        fid = _fid(ctx)
        db.execute(
            "UPDATE consent_records SET user_id = %s, last_updated_at = NOW() WHERE user_id = %s AND fiduciary_id = %s",
            (auth, anon, fid),
        )
        db.execute(
            """
            INSERT INTO data_principal (user_id, fiduciary_id, age_category, guardian_id, verification_status)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (user_id, fiduciary_id) DO UPDATE SET
                age_category = EXCLUDED.age_category,
                guardian_id = EXCLUDED.guardian_id,
                verification_status = EXCLUDED.verification_status
            """,
            (
                auth,
                fid,
                ctx.payload.get("age_category", "ADULT"),
                ctx.payload.get("guardian_id"),
                ctx.payload.get("verification_status", "NOT_VERIFIED"),
            ),
        )
        return {"success": True, "message": "User consent records linked successfully."}

    def validate_consent(self, ctx: RequestContext) -> dict:
        bind_principal_field(ctx, "user_id")
        user_id = require(ctx.payload.get("user_id"), "user_id")
        purpose = require(ctx.payload.get("required_purpose_id"), "required_purpose_id")
        fid = _fid(ctx)
        # CW-03: one active record per policy, so look at all of them. The newest
        # record that names the purpose decides; if none names it, it was never
        # consented to.
        rows = db.all(
            """
            SELECT id, data_point_consents, timestamp, consent_status_general, policy_id, policy_version
            FROM consent_records
            WHERE user_id = %s AND fiduciary_id = %s AND is_active_consent IS TRUE
            ORDER BY timestamp DESC
            """,
            (user_id, fid),
        )
        valid = False
        purpose_state = "NO_CONSENT"
        row = rows[0] if rows else None
        if rows:
            purpose_state = "NOT_CONSENTED"
            for candidate in rows:
                points = [p for p in candidate.get("data_point_consents") or [] if isinstance(p, dict)]
                named = any(
                    str(p.get("data_point_id") or p.get("id") or p.get("purpose_id") or "").lower() == purpose.lower()
                    for p in points
                )
                if named:
                    row = candidate
                    valid = any(_point_grants(p, purpose) for p in points)
                    purpose_state = "GRANTED" if valid else "WITHDRAWN"
                    break
        # PL-02/PL-03: a CLOSED purpose can never validate — closing one must halt
        # further processing under it even if a consent row still exists.
        lifecycle = db.one(
            "SELECT state FROM purpose_lifecycle WHERE fiduciary_id = %s AND purpose_id = %s",
            (fid, purpose),
        )
        if lifecycle and lifecycle["state"] == "CLOSED":
            valid = False
            purpose_state = "PURPOSE_CLOSED"
        db.execute(
            "INSERT INTO consent_validations (fiduciary_id, user_id, purpose_id, status) VALUES (%s, %s, %s, %s)",
            (fid, user_id, purpose, "VALID" if valid else "INVALID"),
        )
        # CV-07: a denied validation must notify the principal, and the denial
        # leaves an audit trail with the purpose and outcome as discrete columns
        # (CV-06, LG-02).
        if not valid:
            _notify_principal(user_id, fid, NOTIF_VALIDATION_DENIED)
            try:
                from ..webhooks import queue_webhook

                queue_webhook(fid, "CONSENT_DENIED", {"user_id": user_id, "purpose_id": purpose})
            except Exception:  # pragma: no cover
                pass
            log_event(
                user_id,
                fid,
                "APP",
                None,
                "CONSENT_VALIDATION_DENIED",
                {"denied_purpose_id": purpose},
                purpose_id=purpose,
                consent_status="INVALID",
                initiator="INTEGRATOR",
                source_ip=ctx.source_ip,
            )
        # CV-04: return the metadata the decision rests on, so the fiduciary can
        # check timestamp and status itself rather than trusting a bare boolean.
        return {
            "valid": valid,
            "status": "VALID" if valid else "INVALID",
            "required_purpose_id": purpose,
            "metadata": {
                "user_id": user_id,
                "purpose_id": purpose,
                "purpose_status": purpose_state,
                "consent_record_id": str(row["id"]) if row else None,
                "consent_timestamp": row["timestamp"].isoformat() if row and row.get("timestamp") else None,
                "consent_status": row["consent_status_general"] if row else None,
                "policy_id": row["policy_id"] if row else None,
                "policy_version": row["policy_version"] if row else None,
            },
        }

    def get_withdrawal_implications(self, ctx: RequestContext) -> dict:
        """CW-04: what withdrawing each consented purpose means, shown before the
        principal confirms — the service impact, and whether the law requires the
        data to be kept anyway."""
        from .retention import legal_hold_for

        bind_principal_field(ctx, "user_id")
        fid = _fid(ctx)
        user_id = require(ctx.payload.get("user_id"), "user_id")
        language = str(ctx.payload.get("language") or "en")
        where = "cr.user_id = %s AND cr.fiduciary_id = %s AND cr.is_active_consent IS TRUE"
        params: list[Any] = [user_id, fid]
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
        wanted = {pid.lower() for pid in _normalise_purpose_ids(ctx.payload)}
        out = []
        seen: set[str] = set()
        granted_points = []
        for record in records:
            content = record.get("policy_content") or {}
            block = content.get(language) or content.get("en") or next(iter(content.values()), {})
            purposes = {
                str(p.get("id")).lower(): p for p in (block.get("data_processing_purposes") or []) if isinstance(p, dict)
            }
            for point in record.get("data_point_consents") or []:
                if isinstance(point, dict) and _point_granted(point):
                    granted_points.append((point, purposes))
        for point, purposes in granted_points:
            pid = str(point.get("data_point_id") or point.get("id") or point.get("purpose_id") or "")
            if (wanted and pid.lower() not in wanted) or pid.lower() in seen:
                continue
            seen.add(pid.lower())
            purpose = purposes.get(pid.lower(), {})
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
        status = "ERASURE_REQUESTED" if erasure else "WITHDRAWN"
        expiry = (datetime.now(UTC) + timedelta(days=RETENTION_CESSATION_DAYS)).isoformat()
        record_id = None
        held: list[dict] = []
        with db.connection() as conn, conn.cursor() as cur:
            # CW-03: one active record per policy. Withdraw from every active record
            # (optionally only the named policy's) that holds a named purpose.
            policy_filter = ctx.payload.get("policy_id")
            cur.execute(
                "SELECT * FROM consent_records WHERE user_id = %s AND fiduciary_id = %s AND is_active_consent IS TRUE"
                + (" AND policy_id = %s" if policy_filter else "")
                + " ORDER BY timestamp DESC FOR UPDATE",
                (user_id, fid, policy_filter) if policy_filter else (user_id, fid),
            )
            active_rows = cur.fetchall()
            if active_rows and purpose_ids:
                # CW-06: every purpose named for withdrawal must currently hold an
                # active grant; withdrawing something that was never granted is an
                # error an integrator can act on, not a silent success.
                granted = {
                    str(p.get("data_point_id") or p.get("id") or p.get("purpose_id") or "").lower()
                    for active in active_rows
                    for p in active["data_point_consents"] or []
                    if isinstance(p, dict) and _point_granted(p)
                }
                missing = [pid for pid in purpose_ids if pid.lower() not in granted]
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
                    isinstance(p, dict)
                    and _point_granted(p)
                    and str(p.get("data_point_id") or p.get("id") or p.get("purpose_id") or "").lower()
                    in {w.lower() for w in purpose_ids}
                    for p in points
                ):
                    continue  # this policy's record holds none of the named purposes
                full_withdrawal = not purpose_ids
                updated: list[Any] = []
                for point in points:
                    if not isinstance(point, dict):
                        updated.append(point)
                        continue
                    stored_id = str(point.get("data_point_id") or point.get("id") or point.get("purpose_id") or "")
                    matches = full_withdrawal or any(stored_id.lower() == wanted.lower() for wanted in purpose_ids)
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
                    """
                    INSERT INTO consent_records
                        (id, user_id, fiduciary_id, policy_id, policy_version, timestamp,
                         jurisdiction, language_selected, consent_status_general, consent_mechanism,
                         ip_address, user_agent, data_point_consents, is_active_consent,
                         verification_log_id, session_id, session_source, client_metadata,
                         supersedes_record_id, created_at, last_updated_at)
                    VALUES (uuid_generate_v4(), %s, %s, %s, %s, NOW(), %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                    RETURNING id
                    """,
                    (
                        row["user_id"],
                        row["fiduciary_id"],
                        row["policy_id"],
                        row["policy_version"],
                        row["jurisdiction"],
                        row["language_selected"],
                        row_status,
                        observed["mechanism"],
                        observed["ip_address"],
                        observed["user_agent"],
                        db.as_jsonb(updated),
                        is_active,
                        row.get("verification_log_id"),
                        observed["session_id"],
                        observed["session_source"],
                        db.as_jsonb(observed["client_metadata"]),
                        row["id"],
                    ),
                )
                record_ids.append(str(cur.fetchone()["id"]))
            record_id = record_ids[0] if record_ids else None
            if erasure:
                from .retention import legal_hold_for

                targets = purpose_ids or ["ALL"]
                for target in targets:
                    # CW-11: decide at withdrawal time whether the law requires the
                    # data to be kept; a held request says so and cites the rule.
                    hold = legal_hold_for(fid, target)
                    cur.execute(
                        """
                        INSERT INTO purge_requests
                            (user_id, fiduciary_id, purpose_id, trigger_event, details, status, legal_reference, hold_until)
                        VALUES (%s, %s, %s, 'ErasureRequest', %s, %s, %s,
                                CASE WHEN %s::int IS NULL THEN NULL ELSE NOW() + make_interval(days => %s::int) END)
                        """,
                        (
                            user_id,
                            fid,
                            target,
                            ctx.payload.get("reason"),
                            "LEGAL_HOLD_APPLIED" if hold else "PENDING",
                            hold["legal_reference"] if hold else None,
                            hold["days"] if hold else None,
                            hold["days"] if hold else None,
                        ),
                    )
                    if hold:
                        held.append({"purpose_id": target, "legal_reference": hold["legal_reference"]})
        _notify_principal(user_id, fid, NOTIF_ERASURE_REQUESTED if erasure else NOTIF_WITHDRAWAL_ACK)
        log_event(
            user_id,
            fid,
            "APP",
            None,
            "ERASURE_REQUESTED" if erasure else "CONSENT_WITHDRAWN",
            {"reason": ctx.payload.get("reason"), "purpose_ids": purpose_ids, "record_id": record_id},
            purpose_id=purpose_ids[0] if purpose_ids and len(purpose_ids) == 1 else None,
            consent_status=status,
            initiator="PRINCIPAL" if ctx.auth_via_principal_jwt else "INTEGRATOR",
            source_ip=ctx.source_ip,
        )
        # CW-08: push a stop signal to linked systems instead of relying on them
        # to poll. Delivery happens through the webhook dispatcher worker.
        try:
            from ..webhooks import queue_webhook

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
        out = {
            "success": True,
            "message": "Erasure request submitted." if erasure else "Consent withdrawn successfully.",
            "consent_record_id": record_id,
            "consent_record_ids": record_ids,
        }
        if held:
            out["retained_under_legal_hold"] = held
        return out


class PrincipalService(Service):
    def list_active_fiduciaries(self, ctx: RequestContext) -> list[dict]:
        return db.to_jsonable(
            db.all(
                # otp_mode tells the rights portal whether to show "Send OTP".
                """
                SELECT f.id AS fiduciary_id, f.name, f.primary_domain, COALESCE(r.otp_mode, 'DUMMY_OTP') AS otp_mode
                FROM fiduciaries f LEFT JOIN rights_app_config r ON r.fiduciary_id = f.id
                WHERE f.status = 'ACTIVE' ORDER BY f.name
                """
            )
        )

    def list_fiduciary_personas(self, ctx: RequestContext) -> list[dict]:
        """Personas a principal can declare pre-login (Customer, Employee, Vendor...).

        Sourced from the data_subject_categories of the fiduciary's active ROPA
        entries. This is a public, unauthenticated endpoint -- it must never expose
        data_principal rows or any other personal data.
        """
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        return db.to_jsonable(
            db.all(
                """
            SELECT DISTINCT
                   lower(replace(trim(cat), ' ', '_')) AS id,
                   trim(cat)                           AS label
            FROM ropa_entries e,
                 LATERAL jsonb_array_elements_text(e.data_subject_categories) AS cat
            WHERE e.fiduciary_id = %s
              AND e.status = 'active'
              AND trim(cat) <> ''
            ORDER BY label
            LIMIT 100
            """,
                (fid,),
            )
        )

    @staticmethod
    def _otp_mode(fid: str) -> tuple[str, str | None]:
        """The fiduciary's configured OTP mode; 404 for an unknown or inactive fiduciary."""
        row = db.one(
            """
            SELECT COALESCE(r.otp_mode, 'DUMMY_OTP') AS otp_mode, r.otp_message_template
            FROM fiduciaries f LEFT JOIN rights_app_config r ON r.fiduciary_id = f.id
            WHERE f.id = %s AND f.status = 'ACTIVE'
            """,
            (fid,),
        )
        if not row:
            raise ApiError(404, "Not Found", "Fiduciary not found or inactive.")
        return str(row["otp_mode"]).upper(), row.get("otp_message_template")

    def request_principal_otp(self, ctx: RequestContext) -> dict:
        """Issue a one-time login code and send it to the principal out of band.

        The code is never returned in the response. Only its HMAC is stored, with
        an expiry; principal_login consumes it exactly once.
        """
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        user_id = str(require(ctx.payload.get("user_id"), "user_id")).strip()
        mode, template = self._otp_mode(fid)
        if mode == "DUMMY_OTP":
            if not principal_otp.dummy_allowed():
                raise ApiError(403, "Forbidden", "Evaluation OTP mode is disabled on this deployment.")
            return {"success": True, "message": "Evaluation mode: no OTP is sent."}
        subject = principal_otp.subject_key(fid, user_id)
        recent = db.one(
            "SELECT COUNT(*) AS count FROM principal_otps WHERE subject_hash = %s AND created_at > NOW() - make_interval(mins => %s)",
            (subject, principal_otp.REQUEST_WINDOW_MINUTES),
        )
        if recent and int(recent["count"]) >= principal_otp.MAX_REQUESTS_PER_WINDOW:
            raise ApiError(429, "Too Many Requests", "Too many OTP requests. Please wait and try again.")
        code = principal_otp.generate_code()
        with db.connection() as conn, conn.cursor() as cur:
            # Only the newest code is ever valid.
            cur.execute(
                "UPDATE principal_otps SET consumed_at = NOW() WHERE subject_hash = %s AND consumed_at IS NULL",
                (subject,),
            )
            cur.execute(
                """
                INSERT INTO principal_otps (fiduciary_id, subject_hash, code_hash, expires_at)
                VALUES (%s, %s, %s, NOW() + make_interval(mins => %s))
                """,
                (fid, subject, principal_otp.code_hash(subject, code), principal_otp.TTL_MINUTES),
            )
        from ..webhooks import queue_webhook

        message = (template or "Your verification code is {{otp}}").replace("{{otp}}", code)
        queue_webhook(
            fid,
            "PRINCIPAL_OTP",
            {
                "channel": "EMAIL" if mode == "EMAIL_OTP" else "SMS",
                "recipient": user_id,
                "otp": code,
                "message": message,
                "expires_in_minutes": principal_otp.TTL_MINUTES,
            },
            category="OTP",
        )
        return {"success": True, "message": "OTP sent.", "expires_in_minutes": principal_otp.TTL_MINUTES}

    def principal_login(self, ctx: RequestContext) -> dict:
        fid = require(ctx.payload.get("fiduciary_id"), "fiduciary_id")
        user_id = str(require(ctx.payload.get("user_id"), "user_id")).strip()
        supplied = str(require(ctx.payload.get("otp"), "otp")).strip()
        mode, _ = self._otp_mode(fid)
        if mode == "DUMMY_OTP":
            if not principal_otp.dummy_allowed() or not principal_otp.dummy_matches(supplied):
                raise ApiError(401, "Unauthorized", "Invalid OTP or account not found.")
        elif not self._consume_otp(fid, user_id, supplied):
            log_event(user_id, fid, "APP", None, "PRINCIPAL_LOGIN_FAILURE", {"reason": "Invalid or expired OTP."})
            raise ApiError(401, "Unauthorized", "Invalid OTP or account not found.")
        log_event(user_id, fid, "APP", None, "PRINCIPAL_LOGIN_SUCCESS", {"otp_mode": mode}, source_ip=ctx.source_ip)
        return {"success": True, "token": principal_token(fid, user_id), "user_id": user_id, "fiduciary_id": fid}

    @staticmethod
    def _consume_otp(fid: str, user_id: str, supplied: str) -> bool:
        """Verify `supplied` against the live code; single-use, expiring, attempt-capped."""
        subject = principal_otp.subject_key(fid, user_id)
        row = db.one(
            """
            SELECT id, code_hash, attempts FROM principal_otps
            WHERE subject_hash = %s AND consumed_at IS NULL AND expires_at > NOW()
            ORDER BY created_at DESC LIMIT 1
            """,
            (subject,),
        )
        if not row:
            return False
        if principal_otp.code_matches(subject, supplied, row["code_hash"]):
            # Consume atomically: a concurrent second login with the same code loses.
            return (
                db.execute(
                    "UPDATE principal_otps SET consumed_at = NOW() WHERE id = %s AND consumed_at IS NULL",
                    (row["id"],),
                )
                == 1
            )
        # A wrong guess burns an attempt; the code dies once the cap is reached.
        db.execute(
            """
            UPDATE principal_otps SET attempts = attempts + 1,
                   consumed_at = CASE WHEN attempts + 1 >= %s THEN NOW() ELSE consumed_at END
            WHERE id = %s
            """,
            (principal_otp.MAX_ATTEMPTS, row["id"]),
        )
        return False


# Wallet sync actions and the concrete function each one runs. dispatch()
# rewrites _func to the target BEFORE authentication, so the API-key scope map,
# the client allow-list and the admin role gate all judge the real operation -
# a READ-scoped key that sends action=GRANT_CONSENT is checked as record_consent.
WALLET_ACTIONS = {
    "GET_CONSENT_DETAILS": "get_consent_record_details",
    "REVOKE_PURPOSE": "erasure_request",
    "GLOBAL_ERASURE": "erasure_request",
    "GRANT_CONSENT": "record_consent",
    "GET_POLICY_PURPOSES": "get_active_policy",
}


def resolve_wallet_action(payload: dict) -> None:
    """Point a wallet call's _func at the function its `action` runs (in place)."""
    # The wallet client sends the action as `command`; `action` is the documented name.
    action = payload.get("action") or payload.get("command")
    if not action and str(payload.get("_func") or "").upper() in WALLET_ACTIONS:
        action = payload["_func"]
    if not action:
        return
    target = WALLET_ACTIONS.get(str(action).upper())
    if not target:
        raise ApiError(400, "Bad Request", f"Unsupported wallet action: {action}")
    payload["_func"] = target


class WalletService(Service):
    def sync(self, ctx: RequestContext) -> dict:
        return {"success": True}

    def handle(self, ctx: RequestContext) -> Any:
        func = ctx.func
        if func == "sync":
            return self.sync(ctx)
        if func == "get_active_policy":
            from .catalog import PolicyService

            return PolicyService().get_active_policy(ctx)
        if func in set(WALLET_ACTIONS.values()):
            return getattr(ConsentService(), func)(ctx)
        raise ApiError(400, "Bad Request", f"Unsupported function: {func}")
