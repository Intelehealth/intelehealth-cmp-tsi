from __future__ import annotations

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.context import RequestContext

GRIEVANCE_TYPES = {
    "GENERAL_COMPLAINT",
    "ERASURE_REQUEST",
    "DATA_ACCESS_REQUEST",
    "CORRECTION_REQUEST",
    "CONSENT_COMPLAINT",
    "DATA_HANDLING_COMPLAINT",
}


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
            "INSERT INTO notifications (recipient_type, recipient_id_enc, recipient_id_hmac, fiduciary_id,"
            f" notification_type, context) VALUES ('PRINCIPAL', {pii.PID_VALUES}, %s, %s, %s)",
            (*pii.pid_params(user_id), fiduciary_id, notice, db.as_jsonb(context) if context else None),
        )


def officer_can_handle_grievances(role: str | None, fiduciary_id: str | None) -> bool:
    """GR-07: an officer a grievance is routed or assigned to must hold
    grievance:write, or the complaint lands with someone who cannot act on it."""
    from dpdpcms_py.modules.administration.api import has_permission, role_permissions

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


def _notify_grievance_assignee(
    operator_id: str, fiduciary_id: str, grievance_id: str, reference_number: str | None, grievance_type: str | None
) -> None:
    """P7-05: the officer a grievance is routed to gets their OWN notice (not the
    principal's copy) naming the grievance, so they know which complaint to act on."""
    db.execute(
        "INSERT INTO notifications (recipient_type, recipient_id_enc, recipient_id_hmac, fiduciary_id,"
        f" notification_type, context) VALUES ('DPO', {pii.PID_VALUES}, %s, 'GRIEVANCE_ROUTED', %s)",
        (
            *pii.pid_params(operator_id),
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
