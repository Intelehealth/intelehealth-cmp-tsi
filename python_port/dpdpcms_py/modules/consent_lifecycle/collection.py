from __future__ import annotations

from typing import Any

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    bind_principal_field,
    canonical_consent_points,
    canonical_purpose_id,
    point_purpose_id,
    reject_principal,
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
from dpdpcms_py.modules.consent_lifecycle.policy_store import served_policy_version

NOTIF_CONSENT_GIVEN = "CONSENT_GIVEN_NOTIFICATION"


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
                ids.add(canonical_purpose_id(purpose["id"]))
    return ids


def check_consent_alignment(fiduciary_id: str, policy_id: str, version: str, data_consents: list[Any]) -> set[str]:
    """CU-05: every purpose in a consent submission must be declared by the policy,
    and no CLOSED purpose (PL-02/03) may be granted. Returns the closed purpose ids
    (lower-case) so the explicit-choice check does not demand a decision on them."""
    policy = db.one(
        "SELECT policy_content, status, effective_date <= NOW() AS in_effect FROM consent_policies WHERE id = %s AND version = %s AND fiduciary_id = %s",
        (policy_id, version, fiduciary_id),
    )
    if not policy:
        raise ApiError(404, "Not Found", f"Policy {policy_id} version {version} not found.")
    # P9-02: consent may only rest on a notice the principal could have been
    # shown, i.e. the version get_active_policy serves: ACTIVE and in effect.
    # A DRAFT was never published and an ARCHIVED version is no longer served.
    # P11-03: several versions can be ACTIVE and in effect until the superseded
    # one is archived; only the newest - the one served - may take consent.
    if (
        str(policy.get("status") or "").upper() != "ACTIVE"
        or policy.get("in_effect") is False
        or served_policy_version(policy_id, fiduciary_id) != str(version)
    ):
        raise ApiError(
            409,
            "Conflict",
            f"Policy {policy_id} version {version} is not the active, in-effect notice; consent cannot be recorded against it.",
        )
    declared = declared_purpose_ids(policy.get("policy_content"))

    requested: set[str] = set()
    granted: set[str] = set()
    if isinstance(data_consents, list):
        for point in data_consents:
            if not isinstance(point, dict):
                continue
            pid = point_purpose_id(point)
            if pid:
                requested.add(pid)
                if point.get("consent_granted") is True:
                    granted.add(pid)
    for pid in requested:
        if pid not in declared:
            raise ApiError(
                400,
                "Bad Request",
                f"Purpose '{pid}' is not declared in policy {policy_id} version {version}.",
            )

    closed = db.all(
        "SELECT purpose_id FROM purpose_lifecycle WHERE fiduciary_id = %s AND state = 'CLOSED'",
        (fiduciary_id,),
    )
    closed_ids = {canonical_purpose_id(row["purpose_id"]) for row in closed}
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
        pid = point_purpose_id(point)
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
    undecided = sorted(d for d in declared_purpose_ids(policy_content) if d not in exempt)
    if undecided:
        raise ApiError(
            400,
            "Bad Request",
            f"No explicit decision for purpose(s) {undecided}; every purpose must be accepted or declined individually.",
        )


class CollectionHandlers:
    def record_consent(self, ctx: RequestContext) -> dict:
        payload = ctx.payload
        bind_principal_field(ctx, "user_id")
        fid = _fid(ctx)
        user_id = require(payload.get("user_id"), "user_id")
        policy_id = require(payload.get("policy_id"), "policy_id")
        # PT-02: the language is a code from the closed list, never free text
        # (it is echoed into the principal's CSV and PDF exports).
        from dpdpcms_py.modules.notifications.api import NOTIFICATION_LANGUAGES

        language = str(payload.get("language_selected") or "en").strip().lower()
        if language not in NOTIFICATION_LANGUAGES:
            raise ApiError(400, "Bad Request", "language_selected must be en or an Eighth Schedule language code.")
        payload["language_selected"] = language
        # P10-01: one purpose per decision, stored under data_point_id only.
        data_consents = canonical_consent_points(require(payload.get("data_point_consents"), "data_point_consents"))
        payload["data_point_consents"] = data_consents
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
            # P11-03: that is the served version when there is one.
            served = served_policy_version(policy_id, fid)
            policy = db.one(
                "SELECT version, policy_content FROM consent_policies WHERE id = %s AND fiduciary_id = %s ORDER BY (version = %s) DESC, (status = 'ACTIVE') DESC, effective_date DESC LIMIT 1",
                (policy_id, fid, served or ""),
            )
            if not policy:
                raise ApiError(400, "Bad Request", f"Policy not found: {policy_id}.")
            version = policy["version"]
        # CU-05: the submission may only reference purposes the policy declares,
        # and never grant a purpose that is CLOSED under the purpose lifecycle.
        closed = check_consent_alignment(fid, policy_id, version, data_consents)
        check_explicit_choices(policy.get("policy_content"), data_consents, closed)
        # SEC-05: age_category is never silently defaulted to ADULT. When the
        # payload names one it is honoured (MINOR still requires a VERIFIED
        # guardian log below); when it is silent the existing value survives via
        # COALESCE. An upsert default overwriting a MINOR row closes the s.9 gate.
        age_category = str(payload["age_category"]).upper() if payload.get("age_category") else None
        guardian_id = payload.get("guardian_id")
        verification_log_id = payload.get("verification_log_id")
        # SEC-05 (residual): the s.9 gate keys off the STORED record, not the
        # body. A principal the CMS already classified as MINOR stays a minor
        # when the request omits age_category (the old code skipped the gate)
        # and cannot be flipped to ADULT over the wire, since nothing downstream
        # compares the two values.
        stored = db.one(
            f"SELECT age_category FROM data_principal WHERE {_USER_MATCH} AND fiduciary_id = %s",
            (*pii.hmac_params(user_id), fid),
        )
        stored_age = str(stored["age_category"]).strip().upper() if stored and stored.get("age_category") else None
        if stored_age == "MINOR" and age_category == "ADULT":
            raise ApiError(
                403,
                "Forbidden",
                "This principal is recorded as a minor; consent can only be recorded with a verified guardian.",
            )
        effective_age = "MINOR" if stored_age == "MINOR" else age_category
        if effective_age == "MINOR":
            # CC-05: a minor's consent always rests on a VERIFIED guardian log;
            # naming a guardian_id alone is an assertion, not a verification.
            where = (
                f"child_principal_id_hmac = {pii.HMAC_SQL} AND fiduciary_id = %s AND verification_status = 'VERIFIED'"
            )
            params: list[Any] = [*db.bind_key(), *pii.hmac_params(user_id), fid]
            if guardian_id:
                where += f" AND guardian_principal_id_hmac = {pii.HMAC_SQL}"
                params.extend(pii.hmac_params(guardian_id))
            if verification_log_id:
                where += " AND id = %s"
                params.append(verification_log_id)
            parent_log = db.one(
                f"SELECT id, {pii.dec_sql('guardian_principal_id_enc')} AS guardian_principal_id"
                f" FROM parental_verification_logs WHERE {where} ORDER BY verified_at DESC LIMIT 1",
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
                "UPDATE consent_records SET is_active_consent = FALSE, last_updated_at = NOW()"
                f" WHERE {_USER_MATCH} AND fiduciary_id = %s AND policy_id = %s AND is_active_consent IS TRUE RETURNING id",
                (*pii.hmac_params(user_id), fid, policy_id),
            )
            prior = cur.fetchone()
            cur.execute(
                f"""
                INSERT INTO consent_records
                    (id, user_id_enc, user_id_hmac, fiduciary_id, policy_id, policy_version, timestamp,
                     jurisdiction, language_selected, consent_status_general, consent_mechanism,
                     ip_address_enc, user_agent, data_point_consents, is_active_consent,
                     verification_log_id, session_id, session_source, client_metadata,
                     supersedes_record_id, created_at, last_updated_at)
                VALUES (uuid_generate_v4(), {pii.ENC_SQL}, {pii.HMAC_SQL}, %s, %s, %s, NOW(), %s, %s, %s, %s,
                        {db.enc_expr()}, %s, %s, TRUE, %s, %s, %s, {_CLIENT_METADATA_SQL}, %s, NOW(), NOW())
                RETURNING id
                """,
                (
                    *pii.enc_params(user_id),
                    *pii.hmac_params(user_id),
                    fid,
                    policy_id,
                    version,
                    payload.get("jurisdiction", "IN"),
                    payload.get("language_selected", "en"),
                    "CONSENT_GIVEN",
                    observed["mechanism"],
                    *db.bind_encrypt(observed["ip_address"]),
                    observed["user_agent"],
                    db.as_jsonb(data_consents),
                    verification_log_id,
                    observed["session_id"],
                    observed["session_source"],
                    db.as_jsonb(observed["client_metadata"]),
                    *db.bind_encrypt(observed["claimed_ip_address"]),
                    prior["id"] if prior else None,
                ),
            )
            cid = str(cur.fetchone()["id"])
            cur.execute(
                f"""
                INSERT INTO data_principal
                    (user_id_enc, user_id_hmac, fiduciary_id, last_consent_mechanism, age_category,
                     guardian_id_enc, guardian_id_hmac, verification_status)
                VALUES ({pii.ENC_SQL}, {pii.HMAC_SQL}, %s, %s, %s, {pii.ENC_SQL}, {pii.HMAC_SQL}, %s)
                ON CONFLICT (user_id_hmac, fiduciary_id) DO UPDATE SET
                    last_consent_mechanism = EXCLUDED.last_consent_mechanism,
                    age_category = COALESCE(EXCLUDED.age_category, data_principal.age_category),
                    guardian_id_enc = COALESCE(EXCLUDED.guardian_id_enc, data_principal.guardian_id_enc),
                    guardian_id_hmac = COALESCE(EXCLUDED.guardian_id_hmac, data_principal.guardian_id_hmac),
                    verification_status = COALESCE(EXCLUDED.verification_status, data_principal.verification_status)
                """,
                (
                    *pii.enc_params(user_id),
                    *pii.hmac_params(user_id),
                    fid,
                    observed["mechanism"],
                    effective_age,
                    *pii.enc_params(guardian_id),
                    *pii.hmac_params(guardian_id),
                    "GUARDIAN_VERIFIED" if effective_age == "MINOR" else None,
                ),
            )
        _notify_principal(user_id, fid, NOTIF_CONSENT_GIVEN)
        grant_purpose_ids = []
        declined_purpose_ids = []
        if isinstance(data_consents, list):
            for point in data_consents:
                pid = point_purpose_id(point)
                if not pid:
                    continue
                if _point_granted(point):
                    grant_purpose_ids.append(pid)
                else:
                    declined_purpose_ids.append(pid)
        # CU-09: the audit row names every purpose the grant or update decided,
        # not only a single-purpose grant's purpose_id column.
        log_event(
            user_id,
            fid,
            "APP",
            None,
            "CONSENT_GIVEN",
            {
                "policy_id": policy_id,
                "policy_version": version,
                "record_id": cid,
                "supersedes_record_id": str(prior["id"]) if prior else None,
                "purpose_ids": grant_purpose_ids + declined_purpose_ids,
                "granted_purpose_ids": grant_purpose_ids,
                "declined_purpose_ids": declined_purpose_ids,
            },
            purpose_id=grant_purpose_ids[0] if len(grant_purpose_ids) == 1 else None,
            consent_status="CONSENT_GIVEN",
            initiator="PRINCIPAL" if ctx.auth_via_principal_jwt else "INTEGRATOR",
            source_ip=ctx.source_ip,
        )
        try:
            from dpdpcms_py.modules.notifications.api import queue_webhook

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

    def link_user(self, ctx: RequestContext) -> dict:
        reject_principal(ctx, "Linking anonymous sessions requires an application API key.")
        anon = require(ctx.payload.get("anonymous_user_id"), "anonymous_user_id")
        auth = require(ctx.payload.get("authenticated_user_id"), "authenticated_user_id")
        fid = _fid(ctx)
        with db.connection() as conn, conn.cursor() as cur:
            db.allow_consent_maintenance(cur)
            cur.execute(
                f"UPDATE consent_records SET user_id_enc = {pii.ENC_SQL}, user_id_hmac = {pii.HMAC_SQL},"
                f" last_updated_at = NOW() WHERE {_USER_MATCH} AND fiduciary_id = %s",
                (*pii.pid_params(auth), *pii.hmac_params(anon), fid),
            )
        # SEC-05: age_category and verification_status are server-derived from
        # the guardian/consent flows (CC-05), never from this payload. The link
        # only relabels an anonymous profile the server already recorded (age
        # and verification intact) when the authenticated user has none of its
        # own; an existing row is never overwritten, and no default 'ADULT'
        # value is fabricated for a user whose age the server has not attested.
        db.execute(
            f"UPDATE data_principal SET user_id_enc = {pii.ENC_SQL}, user_id_hmac = {pii.HMAC_SQL}"
            f" WHERE {_USER_MATCH} AND fiduciary_id = %s"
            f" AND NOT EXISTS (SELECT 1 FROM data_principal p WHERE p.{_USER_MATCH} AND p.fiduciary_id = %s)",
            (*pii.pid_params(auth), *pii.hmac_params(anon), fid, *pii.hmac_params(auth), fid),
        )
        return {"success": True, "message": "User consent records linked successfully."}

    def list_principals(self, ctx: RequestContext) -> list[dict]:
        rows = db.all(
            f"SELECT *, {pii.dec_sql('user_id_enc')} AS user_id, {pii.dec_sql('guardian_id_enc')} AS guardian_id"
            " FROM data_principal WHERE fiduciary_id = %s ORDER BY created_at DESC LIMIT %s",
            (*db.bind_key(), *db.bind_key(), _fid(ctx), int(ctx.payload.get("limit") or 20)),
        )
        # user_ref is the lookup HMAC, never the identifier: the handle by which the
        # console names a masked principal to reveal_user_id (source data_principal).
        return [
            {**pii.principal_row(ctx, row, "user_id", "guardian_id"), "user_ref": row["user_id_hmac"]} for row in rows
        ]
