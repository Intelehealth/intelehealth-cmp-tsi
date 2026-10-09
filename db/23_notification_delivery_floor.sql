-- ============================================================================
-- db/23_notification_delivery_floor.sql
--
-- P5-07 residual (workbook v6): the Rule 6(1)(e) one-year floor was only
-- enforced in ONE python function, so a direct DELETE bypassed it, and
-- notification_deliveries had no policy or control at all — only a code
-- comment. audit_logs is protected by db/19's append-only trigger; this closes
-- the same gap for notification_deliveries with a database-enforced floor.
--
-- A delivery row is personal-data bearing (recipient address/device and the
-- rendered notification), so deleting it before the one-year floor is exactly
-- what Rule 6(1)(e) forbids. Status updates (PENDING -> PROCESSING -> SENT /
-- FAILED) remain allowed; only DELETE is gated.
--
-- Idempotent: the function and trigger are created conditionally.
-- ============================================================================

CREATE OR REPLACE FUNCTION enforce_notification_delivery_floor() RETURNS trigger AS $$
BEGIN
    IF OLD.created_at > NOW() - INTERVAL '365 days' THEN
        RAISE EXCEPTION 'Rule 6(1)(e): notification_deliveries rows may not be deleted before the one-year floor';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS notification_deliveries_floor ON notification_deliveries;
CREATE TRIGGER notification_deliveries_floor
    BEFORE DELETE ON notification_deliveries
    FOR EACH ROW EXECUTE FUNCTION enforce_notification_delivery_floor();