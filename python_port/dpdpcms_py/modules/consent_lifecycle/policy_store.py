from __future__ import annotations

from typing import Any

from dpdpcms_py.kernel import db
from dpdpcms_py.modules.audit_logging.ledger import log_event


def _policy_purposes(policy_content: Any) -> list[dict]:
    """Purpose objects of the first language block that declares any."""
    if not isinstance(policy_content, dict):
        return []
    for block in policy_content.values():
        if isinstance(block, dict):
            purposes = block.get("data_processing_purposes") or []
            if isinstance(purposes, list):
                return [p for p in purposes if isinstance(p, dict)]
    return []


def queue_policy_change_notices(
    fiduciary_id: str, policy_id: str, new_version: str, reason: str | None = None
) -> dict[str, int]:
    """CU-02/CU-03: notify principals on a materially changed policy and require fresh consent.

    Finds every principal holding active consent on an earlier version of this
    policy, raises a PRINCIPAL notification and a PENDING re-consent request for
    each. Delivery is handled by the notification adapter worker; the principal
    responds through the /client request_reconsent endpoint.
    """
    fid = str(fiduciary_id)
    # One row per principal (HMAC); the encrypted pair is copied as stored.
    holders = db.all(
        """
        SELECT DISTINCT ON (cr.user_id_hmac) cr.user_id_enc, cr.user_id_hmac
        FROM consent_records cr
        WHERE cr.fiduciary_id = %s AND cr.policy_id = %s AND cr.policy_version <> %s
          AND cr.is_active_consent IS TRUE
        """,
        (fid, policy_id, new_version),
    )
    notified = 0
    for holder in holders:
        user_enc, user_hmac = holder["user_id_enc"], holder["user_id_hmac"]
        try:
            db.execute(
                """
                INSERT INTO reconsent_requests (fiduciary_id, policy_id, policy_version, user_id_enc, user_id_hmac, reason)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (fiduciary_id, policy_id, policy_version, user_id_hmac) DO NOTHING
                """,
                (fid, policy_id, new_version, user_enc, user_hmac, reason),
            )
            db.execute(
                """
                INSERT INTO notifications (recipient_type, recipient_id_enc, recipient_id_hmac, fiduciary_id,
                                           notification_type)
                VALUES ('PRINCIPAL', %s, %s, %s, 'POLICY_CHANGE_RECONSENT_REQUIRED')
                """,
                (user_enc, user_hmac, fid),
            )
            notified += 1
        except Exception:
            continue
    return {"principals_affected": len(holders), "notified": notified}


def served_policy_version(policy_id: str, fiduciary_id: str) -> str | None:
    """P11-03: the one version of a policy that is served - ACTIVE, in effect,
    and the newest such. get_active_policy and the consent gate both use it, so
    consent can only rest on the notice a principal is actually shown."""
    row = db.one(
        "SELECT version FROM consent_policies WHERE id = %s AND fiduciary_id = %s AND status = 'ACTIVE' AND effective_date <= NOW() ORDER BY effective_date DESC, last_updated_at DESC, created_at DESC LIMIT 1",
        (policy_id, str(fiduciary_id)),
    )
    return str(row["version"]) if row else None


def retire_superseded_versions(policy_id: str, fiduciary_id: str) -> list[str]:
    """P11-03: once a newer version is in force, the ones it supersedes are
    archived and their unanswered re-consent demands closed.

    Only versions already in effect are retired: a future-dated ACTIVE version
    leaves the current one served until its effective date. Consent records
    that rest on a retired version are untouched - they stay valid until the
    principal answers the re-consent request for the served version.
    """
    fid = str(fiduciary_id)
    served = served_policy_version(policy_id, fid)
    if served is None:
        return []
    retired = [
        str(r["version"])
        for r in db.all(
            "UPDATE consent_policies SET status = 'ARCHIVED', last_updated_at = NOW() WHERE id = %s AND fiduciary_id = %s AND status = 'ACTIVE' AND effective_date <= NOW() AND version <> %s RETURNING version",
            (policy_id, fid, served),
        )
    ]
    closed = db.execute(
        "UPDATE reconsent_requests SET status = 'CLOSED', responded_at = NOW() WHERE fiduciary_id = %s AND policy_id = %s AND policy_version <> %s AND status = 'PENDING'",
        (fid, policy_id, served),
    )
    if retired or closed:
        log_event(
            "SYSTEM",
            fid,
            "DPO_CONSOLE",
            None,
            "POLICY_VERSIONS_SUPERSEDED",
            {
                "policy_id": policy_id,
                "served_version": served,
                "archived_versions": retired,
                "reconsent_closed": closed,
            },
        )
    return retired


def retire_all_superseded_versions() -> dict[str, int]:
    """P11-03 (worker): a future-dated version supersedes the old one when its
    effective date arrives, which no API call marks - so the sweep does it."""
    archived = 0
    for row in db.all(
        "SELECT DISTINCT id, fiduciary_id FROM consent_policies p WHERE status = 'ACTIVE' AND effective_date <= NOW() AND EXISTS (SELECT 1 FROM consent_policies q WHERE q.id = p.id AND q.fiduciary_id = p.fiduciary_id AND q.status = 'ACTIVE' AND q.effective_date <= NOW() AND q.version <> p.version)"
    ):
        archived += len(retire_superseded_versions(str(row["id"]), str(row["fiduciary_id"])))
    return {"archived": archived}
