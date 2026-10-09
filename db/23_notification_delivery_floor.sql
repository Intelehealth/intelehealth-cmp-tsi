-- ============================================================================
-- db/23_notification_delivery_floor.sql
--
-- P5-07 / P7-04: the Rule 6(1)(e) one-year floor on retention of personal data.
--
-- The Python clamp in jobs.prune_old_webhook_deliveries only guards one call
-- path, so this migration makes the floor a DATABASE control for the two
-- delivery/log tables that carry personal data:
--   * notification_deliveries  (recipient address/device + rendered message)
--   * webhook_deliveries       (event payloads for consent, OTP, purge, ...)
--
-- A row younger than the one-year floor may not be DELETEd, and neither table
-- may be TRUNCATEd (the ops-script case that a row trigger alone cannot stop).
-- Status updates (PENDING -> PROCESSING -> SENT / FAILED) remain allowed; only
-- deletion and truncation are gated. audit_logs is already protected by db/19's
-- append-only (UPDATE/DELETE/TRUNCATE) trigger.
--
-- Idempotent: functions and triggers are created/dropped conditionally.
-- ============================================================================

CREATE OR REPLACE FUNCTION enforce_delivery_retention_floor() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'Rule 6(1)(e): % may not be TRUNCATEd - the one-year floor applies', TG_TABLE_NAME;
    END IF;
    IF OLD.created_at > NOW() - INTERVAL '365 days' THEN
        RAISE EXCEPTION 'Rule 6(1)(e): % rows may not be deleted before the one-year floor', TG_TABLE_NAME;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- ---- notification_deliveries ------------------------------------------------
DROP TRIGGER IF EXISTS trg_notification_deliveries_floor ON notification_deliveries;
CREATE TRIGGER trg_notification_deliveries_floor
    BEFORE DELETE ON notification_deliveries
    FOR EACH ROW EXECUTE FUNCTION enforce_delivery_retention_floor();

DROP TRIGGER IF EXISTS trg_notification_deliveries_no_truncate ON notification_deliveries;
CREATE TRIGGER trg_notification_deliveries_no_truncate
    BEFORE TRUNCATE ON notification_deliveries
    FOR EACH STATEMENT EXECUTE FUNCTION enforce_delivery_retention_floor();

-- ---- webhook_deliveries -----------------------------------------------------
DROP TRIGGER IF EXISTS trg_webhook_deliveries_floor ON webhook_deliveries;
CREATE TRIGGER trg_webhook_deliveries_floor
    BEFORE DELETE ON webhook_deliveries
    FOR EACH ROW EXECUTE FUNCTION enforce_delivery_retention_floor();

DROP TRIGGER IF EXISTS trg_webhook_deliveries_no_truncate ON webhook_deliveries;
CREATE TRIGGER trg_webhook_deliveries_no_truncate
    BEFORE TRUNCATE ON webhook_deliveries
    FOR EACH STATEMENT EXECUTE FUNCTION enforce_delivery_retention_floor();