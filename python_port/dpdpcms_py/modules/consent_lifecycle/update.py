from __future__ import annotations

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext
from dpdpcms_py.kernel.errors import ApiError
from dpdpcms_py.kernel.service import (
    bind_principal_field,
    canonical_consent_points,
    canonical_purpose_id,
    point_purpose_id,
    reject_operator,
    require,
)
from dpdpcms_py.modules.administration.api import authenticated_user_id, resolve_fiduciary
from dpdpcms_py.modules.audit_logging.ledger import log_event
from dpdpcms_py.modules.consent_lifecycle.policy_store import (
    _policy_purposes,
    queue_policy_change_notices,
    retire_superseded_versions,
    served_policy_version,
)


class PolicyUpdateHandlers:
    def notify_policy_change(self, ctx: RequestContext) -> dict:
        """CU-02: notify affected principals of a changed policy (idempotent replay)."""
        reject_operator(ctx)
        pid = require(ctx.payload.get("policy_id"), "policy_id")
        version = ctx.payload.get("version") or ""
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        # P10-02: never ask for re-consent to a version consent cannot rest on.
        # P11-03: and only to the version served now, retiring what it supersedes.
        if served_policy_version(pid, fid) != str(version):
            raise ApiError(
                409,
                "Conflict",
                f"Policy {pid} version {version} is not the active, in-effect notice; principals cannot re-consent to it yet.",
            )
        retire_superseded_versions(pid, fid)
        counts = queue_policy_change_notices(fid, pid, version, reason=ctx.payload.get("change_reason"))
        log_event(
            authenticated_user_id(ctx) or "DPO",
            fid,
            "DPO_CONSOLE",
            None,
            "POLICY_CHANGE_NOTIFIED",
            {"policy_id": pid, "version": version, **counts},
        )
        return {"success": True, "policy_id": pid, "version": version, **counts}

    def request_reconsent(self, ctx: RequestContext) -> dict:
        """CU-03: a principal confirms fresh affirmative consent on the new policy version."""
        payload = ctx.payload
        bind_principal_field(ctx, "user_id")
        fid = require(resolve_fiduciary(ctx), "fiduciary_id")
        policy_id = require(payload.get("policy_id"), "policy_id")
        version = payload.get("version") or payload.get("policy_version") or ""
        user_id = require(payload.get("user_id"), "user_id")

        pending = db.one(
            "SELECT id FROM reconsent_requests WHERE fiduciary_id = %s AND policy_id = %s AND policy_version = %s"
            f" AND {pii.match_sql('user_id')} AND status = 'PENDING'",
            (fid, policy_id, version, *pii.hmac_params(user_id)),
        )
        if not pending:
            raise ApiError(
                400,
                "Bad Request",
                "No pending re-consent request exists for this principal, policy and version.",
            )

        consent = db.one(
            "SELECT policy_content FROM consent_policies WHERE id = %s AND version = %s AND fiduciary_id = %s",
            (policy_id, version, fid),
        )
        if not consent:
            raise ApiError(404, "Not Found", f"Policy {policy_id} version {version} not found.")
        declared = {canonical_purpose_id(p.get("id")) for p in _policy_purposes(consent.get("policy_content"))}

        data_consents = require(payload.get("data_point_consents"), "data_point_consents")
        if not isinstance(data_consents, list):
            raise ApiError(400, "Bad Request", "data_point_consents must be an array.")
        # P10-01: same alias rule as record_consent, applied before the check.
        data_consents = canonical_consent_points(data_consents)
        payload["data_point_consents"] = data_consents
        for point in data_consents:
            if not isinstance(point, dict):
                raise ApiError(400, "Bad Request", "data_point_consents entries must be objects.")
            purpose_id = point_purpose_id(point)
            if not purpose_id or purpose_id not in declared:
                raise ApiError(
                    400,
                    "Bad Request",
                    f"Purpose '{purpose_id}' is not declared in policy {policy_id} version {version} (CU-05).",
                )

        from dpdpcms_py.modules.consent_lifecycle.service import ConsentService

        record = ConsentService().record_consent(ctx)
        record_id = record.get("data", {}).get("consent_record_id")
        db.execute(
            "UPDATE reconsent_requests SET status = 'GRANTED', responded_at = NOW(), consent_record_id = %s WHERE id = %s",
            (record_id, pending["id"]),
        )
        log_event(
            user_id,
            fid,
            "APP",
            None,
            "RECONSENT_GRANTED",
            {"policy_id": policy_id, "version": version, "reconsent_request_id": str(pending["id"])},
        )
        return {"success": True, "reconsent_request_id": str(pending["id"]), "status": "GRANTED"}
