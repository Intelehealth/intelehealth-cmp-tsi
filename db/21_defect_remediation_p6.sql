-- ============================================================================
-- db/21_defect_remediation_p6.sql
--
-- Migration for the p6 defect-remediation branch (MeitY_BRD_API_Traceability_
-- security_v2.xlsx, "Defect Remediation"/"Security Gaps" sheets).
--
-- Idempotent: safe to apply to an existing deployment alongside 13..20.
-- ============================================================================

-- ============================================================
-- P5-02: exponential backoff needs the previous lock's duration
-- so the throttle can double it (15m -> 30m -> 1h cap). The
-- counter-decay fix itself lives in python module throttle.py.
-- ============================================================
ALTER TABLE auth_throttles
    ADD COLUMN IF NOT EXISTS lockout_minutes INTEGER;

-- ============================================================
-- SEC-13 one-off cleanup: webhook_deliveries rows queued BEFORE
-- the SEC-13 fix hold the OTP code in the clear (payload ->> 'otp').
-- The dispatcher now ships only otp_enc, so any row that still carries
-- the plaintext key predates the fix. Delete them now rather than
-- letting the 30-day (now one-year) prune keep the codes around.
-- ============================================================
DELETE FROM webhook_deliveries
WHERE payload ? 'otp';

-- ============================================================
-- P5-07: webhook_deliveries is the channel of record for consent
-- events and OTP dispatch, so the retention floor for terminal rows
-- is 365 days (Rule 6(1)(e) one-year floor), configured at runtime
-- via WEBHOOK_DELIVERY_RETENTION_DAYS. No column change is needed:
-- jobs.prune_old_webhook_deliveries reads the setting. audit_logs
-- and notification_deliveries are not pruned (append-only ledger /
-- notification per-delivery history), so they already satisfy a
-- one-year floor by construction.
-- ============================================================