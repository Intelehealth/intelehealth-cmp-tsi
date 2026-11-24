from __future__ import annotations

from datetime import UTC, datetime, timedelta

from dpdpcms_py.kernel import db, pii
from dpdpcms_py.kernel.config import settings
from dpdpcms_py.modules.audit_logging.ledger import log_event
from dpdpcms_py.modules.notifications.api import _dpo_recipient, _notify


def _claim_pending_purges(fiduciary_id: str, purpose_id: str, trigger: str) -> bool:
    # purge_requests.purpose_id is canonical (db/26), as is every lifecycle id
    # this is called with, so an exact match is the canonical match (P10-09).
    """True when no non-terminal purge request already covers (fid, purpose, trigger)."""
    row = db.one(
        """
        SELECT 1 FROM purge_requests
        WHERE fiduciary_id = %s AND purpose_id = %s AND trigger_event = %s
          AND status IN ('PENDING', 'IN_PROGRESS')
        LIMIT 1
        """,
        (fiduciary_id, purpose_id, trigger),
    )
    return row is None


def _retention_for(fiduciary_id: str, purpose_id: str) -> tuple[int | None, str | None]:
    """(retention_period_days, retention_start_event) for a closed purpose.

    P8-07: the lookup lives in services.retention (retention_for /
    retention_for_purposes) so request handlers do not reach into the jobs
    module; kept here for the sweep's existing call sites.
    """
    from dpdpcms_py.modules.administration.retention import retention_for

    return retention_for(fiduciary_id, purpose_id)


def _cessation_for(fiduciary_id: str, purpose_id: str) -> datetime | None:
    """Latest moment processing ceased for a purpose: purpose closure, else last withdrawal."""
    closed = db.one(
        "SELECT closed_at FROM purpose_lifecycle WHERE fiduciary_id = %s AND purpose_id = %s AND state = 'CLOSED'",
        (fiduciary_id, purpose_id),
    )
    if closed and closed.get("closed_at"):
        return closed["closed_at"]
    row = db.one(
        """
        SELECT MAX(cr.last_updated_at) AS cessation
        FROM consent_records cr,
             LATERAL jsonb_array_elements(cr.data_point_consents) AS p
        WHERE cr.fiduciary_id = %s
          AND lower(btrim(COALESCE(p ->> 'data_point_id', p ->> 'purpose_id', p ->> 'id'))) = lower(btrim(%s))
          AND (p ->> 'consent_granted' = 'false' OR lower(p ->> 'status') = 'withdrawn')
        """,
        (fiduciary_id, purpose_id),
    )
    return row["cessation"] if row else None


def _expiry_action(fiduciary_id: str, purpose_id: str) -> str:
    """PL-03: ERASE or DE_IDENTIFY for a purge raised at retention expiry — the
    retention policy's action_at_expiry, else the action chosen at closure."""
    from dpdpcms_py.modules.administration.retention import applicable_policy

    policy = applicable_policy(fiduciary_id, purpose_id)
    if policy and policy.get("action_at_expiry"):
        return str(policy["action_at_expiry"]).upper()
    row = db.one(
        "SELECT deidentification_action FROM purpose_lifecycle WHERE fiduciary_id = %s AND purpose_id = %s",
        (fiduciary_id, purpose_id),
    )
    return str((row or {}).get("deidentification_action") or "ERASE").upper()


def release_expired_legal_holds() -> dict[str, int]:
    """CW-11: a legal hold lasts for the retention period it cites; once that
    ends the request becomes an ordinary pending purge."""
    released = db.execute(
        """
        UPDATE purge_requests SET status = 'PENDING', last_updated_at = NOW(),
               details = COALESCE(details || ' ', '') || '[legal hold expired]'
        WHERE status = 'LEGAL_HOLD_APPLIED' AND hold_until IS NOT NULL AND hold_until < NOW()
        """
    )
    return {"released": released or 0}


def prune_revoked_tokens() -> dict[str, int]:
    """SA-05: a revoked token only needs remembering until it would have expired anyway."""
    return {"pruned": db.execute("DELETE FROM revoked_tokens WHERE expires_at < NOW()") or 0}


def expire_lapsed_api_keys() -> dict[str, int]:
    """SEC-07: mark keys whose expires_at has passed as EXPIRED so the listing
    and the enforced behaviour (security.api_key_valid) always agree.

    Enforcement already rejects an expired key at authenticate time; until this
    sweep runs the console still shows such a key as ACTIVE, which is exactly
    the mismatch the finding called out.
    """
    updated = db.execute(
        "UPDATE api_keys SET status = 'EXPIRED', last_used_at = last_used_at"
        " WHERE status = 'ACTIVE' AND expires_at IS NOT NULL AND expires_at < NOW()"
    )
    return {"expired": updated or 0}


def prune_sso_nonces() -> dict[str, int]:
    """SEC-14: drop SSO login nonces past the token lifetime; a nonce can never
    be presented again once its id_token would have expired anyway."""
    return {"pruned": db.execute("DELETE FROM sso_login_nonces WHERE expires_at < NOW()") or 0}


# Rule 6(1)(c): logs are only half the clause - something must watch them.
# A burst of failed sign-ins within the window raises an acknowledgeable alert
# and tells the DPO, at most once per window per fiduciary.
SECURITY_FAILURE_ACTIONS = ("LOGIN_FAILURE", "PRINCIPAL_LOGIN_FAILURE", "MFA_VERIFY_FAILED")


SECURITY_FAILURE_THRESHOLD = 20


SECURITY_WINDOW_MINUTES = 60


def flag_security_anomalies() -> dict[str, int]:
    """R6-c: alert on bursts of failed authentication, and on identifier reveal volume, recorded in the ledger."""
    from dpdpcms_py.modules.notifications.api import record_alert

    bursts = db.all(
        """
        SELECT a.fiduciary_id, COUNT(*) AS failures
        FROM audit_logs a JOIN fiduciaries f ON f.id = a.fiduciary_id
        WHERE a.audit_action = ANY(%s)
          AND a.timestamp > (NOW() AT TIME ZONE 'UTC') - make_interval(mins => %s)
        GROUP BY a.fiduciary_id
        HAVING COUNT(*) >= %s
        """,
        (list(SECURITY_FAILURE_ACTIONS), SECURITY_WINDOW_MINUTES, SECURITY_FAILURE_THRESHOLD),
    )
    raised = 0
    for row in bursts:
        fid = str(row["fiduciary_id"])
        recent = db.one(
            "SELECT 1 FROM alerts WHERE fiduciary_id = %s AND alert_type = 'SECURITY_AUTH_FAILURE_BURST'"
            " AND created_at > NOW() - make_interval(mins => %s) LIMIT 1",
            (fid, SECURITY_WINDOW_MINUTES),
        )
        if recent:
            continue
        record_alert(
            fid,
            "SECURITY_AUTH_FAILURE_BURST",
            None,
            {"failures": int(row["failures"]), "window_minutes": SECURITY_WINDOW_MINUTES},
        )
        _notify(
            "DPO",
            _dpo_recipient(fid),
            fid,
            "SECURITY_AUTH_FAILURE_BURST",
            {"failures": int(row["failures"]), "window_minutes": SECURITY_WINDOW_MINUTES},
        )
        raised += 1
    raised += _flag_reveal_volume(record_alert)
    return {"alerts_raised": raised}


# P16-05: reveals of principal identifiers (PII_REVEALED) by one operator in one
# tenant above this many per window alert the DPO, once per window.
REVEAL_VOLUME_THRESHOLD = 50


REVEAL_VOLUME_WINDOW_MINUTES = 60


def _flag_reveal_volume(record_alert) -> int:
    from dpdpcms_py.modules.administration.pii_reveal import REVEAL_ACTION

    rows = db.all(
        """
        SELECT a.fiduciary_id, a.initiator, COUNT(*) AS reveals
        FROM audit_logs a JOIN fiduciaries f ON f.id = a.fiduciary_id
        WHERE a.audit_action = %s
          AND a.timestamp > (NOW() AT TIME ZONE 'UTC') - make_interval(mins => %s)
        GROUP BY a.fiduciary_id, a.initiator
        HAVING COUNT(*) >= %s
        """,
        (REVEAL_ACTION, REVEAL_VOLUME_WINDOW_MINUTES, REVEAL_VOLUME_THRESHOLD),
    )
    raised = 0
    for row in rows:
        fid = str(row["fiduciary_id"])
        operator = str(row["initiator"] or "")
        recent = db.one(
            "SELECT 1 FROM alerts WHERE fiduciary_id = %s AND alert_type = 'SECURITY_PII_REVEAL_VOLUME'"
            " AND event_ref_id = %s AND created_at > NOW() - make_interval(mins => %s) LIMIT 1",
            (fid, operator, REVEAL_VOLUME_WINDOW_MINUTES),
        )
        if recent:
            continue
        context = {"operator": operator, "reveals": int(row["reveals"]), "window_minutes": REVEAL_VOLUME_WINDOW_MINUTES}
        record_alert(fid, "SECURITY_PII_REVEAL_VOLUME", operator, context)
        _notify("DPO", _dpo_recipient(fid), fid, "SECURITY_PII_REVEAL_VOLUME", context)
        raised += 1
    return raised


def run_retention_sweep() -> dict[str, int]:
    """PL-04 / SA-09 / SA-11: run the retention clock from cessation, independently of
    consent state, and warn administrators 48 hours before a scheduled deletion."""
    purposes = db.all("SELECT DISTINCT purpose_id, fiduciary_id FROM purpose_lifecycle WHERE state = 'CLOSED'")
    created = 0
    notices = 0
    for row in purposes:
        fid = str(row["fiduciary_id"])
        purpose_id = str(row["purpose_id"])
        retention_days, _start = _retention_for(fid, purpose_id)
        if not retention_days:
            continue
        cessation = _cessation_for(fid, purpose_id)
        if not cessation:
            cessation = datetime.now(UTC)
        due = cessation + timedelta(days=int(retention_days))
        window = (due - datetime.now(UTC)).total_seconds() / 3600.0
        if window <= 0:
            if _claim_pending_purges(fid, purpose_id, "RetentionPolicyExpiry"):
                rowcount = db.execute(
                    """
                    INSERT INTO purge_requests
                        (user_id_enc, user_id_hmac, fiduciary_id, purpose_id, trigger_event, details, action)
                    SELECT DISTINCT ON (cr.user_id_hmac)
                           cr.user_id_enc, cr.user_id_hmac, cr.fiduciary_id, %s, 'RetentionPolicyExpiry', %s, %s
                    FROM consent_records cr,
                         LATERAL jsonb_array_elements(cr.data_point_consents) AS p
                    WHERE cr.fiduciary_id = %s
                      AND lower(btrim(COALESCE(p ->> 'data_point_id', p ->> 'purpose_id', p ->> 'id'))) = lower(btrim(%s))
                      AND NOT EXISTS (
                            SELECT 1 FROM purge_requests pr
                            WHERE pr.user_id_hmac = cr.user_id_hmac
                              AND pr.fiduciary_id = cr.fiduciary_id
                              AND pr.purpose_id = %s
                              AND pr.trigger_event = 'RetentionPolicyExpiry'
                              AND pr.status IN ('PENDING', 'IN_PROGRESS')
                          )
                    """,
                    (
                        purpose_id,
                        f"Retention period of {retention_days} days elapsed from cessation {due.isoformat()} (PL-04).",
                        _expiry_action(fid, purpose_id),
                        fid,
                        purpose_id,
                        purpose_id,
                    ),
                )
                created += rowcount or 0
                _notify("DPO", _dpo_recipient(fid), fid, "PURGE_EXECUTED")
        elif window <= float(settings.purge_notice_hours):
            existing = db.one(
                f"""
                SELECT 1 FROM notifications
                WHERE fiduciary_id = %s AND notification_type = 'PURGE_SCHEDULED'
                  AND {pii.match_sql("recipient_id")} AND created_at > NOW() - INTERVAL '24 hours'
                LIMIT 1
                """,
                (fid, *pii.hmac_params(_dpo_recipient(fid))),
            )
            if not existing:
                _notify("DPO", _dpo_recipient(fid), fid, "PURGE_SCHEDULED")
                notices += 1
                log_event(
                    "SYSTEM",
                    fid,
                    "SYSTEM",
                    None,
                    "PURGE_SCHEDULED",
                    {"purpose_id": purpose_id, "due": due.isoformat(), "notice_hours": settings.purge_notice_hours},
                )
    return {"purge_requests_created": created, "admin_notices": notices}
