-- ============================================================================
-- db/24_p8_remediation.sql
--
-- Workbook v6 remediation. Idempotent; safe to re-run.
--
--   P7-04  The Rule 6(1)(e) floor gated DELETE and TRUNCATE but not UPDATE, so
--          the personal-data fields could still be blanked in place. Within the
--          one-year floor, notification_deliveries.recipient and
--          webhook_deliveries.payload may now change ONLY to the erasure
--          pseudonym ('erased:...') that erase_cms_copy writes; the identity
--          columns of both tables are immutable. Status/attempt bookkeeping is
--          unaffected.
--   P8-03  notification_deliveries cascades from notifications, so deleting a
--          young notifications row raised from a table the caller never named.
--          The floor is now enforced on notifications itself, with a message
--          that names the real cause.
--   P6-12  The chain verifier's ORDER BY timestamp DESC, id DESC had no
--          supporting index (EXPLAIN: Seq Scan + Sort). Added. The full-ledger
--          walk also moves to the worker, which records its verdict here.
--   GR-07  grievance_routing_rules routes a complaint category to a department
--          and its officer (DPO fallback); grievances.department records it.
--   P7-05  notifications.context carries per-notification fields (a grievance
--          reference) that the message template interpolates.
-- ============================================================================

-- ---- P7-05: notification context -------------------------------------------
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS context JSONB;

-- ---- P6-12: index and background verification record ------------------------
-- CONCURRENTLY: log_event inserts on the hot path must not block while the
-- index builds on a large ledger. psql -f runs it outside a transaction block;
-- do not wrap this file in BEGIN/COMMIT or run it with psql -1.
-- An interrupted CONCURRENTLY build leaves an INVALID index that IF NOT EXISTS
-- would then skip; drop such a leftover so the re-run actually builds it.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
        WHERE c.relname = 'idx_audit_logs_chain_order' AND NOT i.indisvalid
    ) THEN
        DROP INDEX idx_audit_logs_chain_order;
    END IF;
END $$;
-- db/32 makes audit_logs partitioned (with this index), and Postgres refuses
-- CONCURRENTLY on a partitioned table even under IF NOT EXISTS; build only
-- when the index is missing so this file stays re-runnable after db/32.
SELECT to_regclass('public.idx_audit_logs_chain_order') IS NULL AS tsi_need_chain_order_idx \gset
\if :tsi_need_chain_order_idx
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_chain_order ON audit_logs (timestamp DESC, id DESC);
\endif

CREATE TABLE IF NOT EXISTS audit_chain_verifications (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    verified_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    intact            BOOLEAN NOT NULL,
    rows_checked      BIGINT NOT NULL,
    broken_count      INTEGER NOT NULL,
    truncated         BOOLEAN NOT NULL,
    coverage_complete BOOLEAN NOT NULL,
    result            JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_chain_verifications_at ON audit_chain_verifications (verified_at DESC);

-- ---- P7-04: UPDATE floor on the personal-data columns ----------------------
CREATE OR REPLACE FUNCTION enforce_notification_delivery_update_floor() RETURNS trigger AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.notification_id IS DISTINCT FROM OLD.notification_id
       OR NEW.channel IS DISTINCT FROM OLD.channel
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'Rule 6(1)(e): notification_deliveries identity columns are immutable';
    END IF;
    IF OLD.created_at > NOW() - INTERVAL '365 days'
       AND NEW.recipient IS DISTINCT FROM OLD.recipient
       AND COALESCE(NEW.recipient, '') NOT LIKE 'erased:%' THEN
        RAISE EXCEPTION 'Rule 6(1)(e): notification_deliveries.recipient may not be altered before the one-year floor except by erasure';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_notification_deliveries_update_floor ON notification_deliveries;
CREATE TRIGGER trg_notification_deliveries_update_floor
    BEFORE UPDATE ON notification_deliveries
    FOR EACH ROW EXECUTE FUNCTION enforce_notification_delivery_update_floor();

CREATE OR REPLACE FUNCTION enforce_webhook_delivery_update_floor() RETURNS trigger AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.fiduciary_id IS DISTINCT FROM OLD.fiduciary_id
       OR NEW.category IS DISTINCT FROM OLD.category
       OR NEW.event_type IS DISTINCT FROM OLD.event_type
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'Rule 6(1)(e): webhook_deliveries identity columns are immutable';
    END IF;
    -- The only permitted payload change inside the floor is erase_cms_copy
    -- re-keying user_id to its pseudonym; every other key must be unchanged.
    IF OLD.created_at > NOW() - INTERVAL '365 days'
       AND NEW.payload IS DISTINCT FROM OLD.payload
       AND NOT (
           (NEW.payload - 'user_id') = (OLD.payload - 'user_id')
           AND COALESCE(NEW.payload ->> 'user_id', '') LIKE 'erased:%'
       ) THEN
        RAISE EXCEPTION 'Rule 6(1)(e): webhook_deliveries.payload may not be altered before the one-year floor except by erasure';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_webhook_deliveries_update_floor ON webhook_deliveries;
CREATE TRIGGER trg_webhook_deliveries_update_floor
    BEFORE UPDATE ON webhook_deliveries
    FOR EACH ROW EXECUTE FUNCTION enforce_webhook_delivery_update_floor();

-- ---- P8-03: name the real cause when a notification is deleted --------------
CREATE OR REPLACE FUNCTION enforce_notification_floor() RETURNS trigger AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM notification_deliveries d
        WHERE d.notification_id = OLD.id AND d.created_at > NOW() - INTERVAL '365 days'
    ) THEN
        RAISE EXCEPTION 'Rule 6(1)(e): notification % has delivery records younger than the one-year floor and may not be deleted', OLD.id;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_notifications_floor ON notifications;
CREATE TRIGGER trg_notifications_floor
    BEFORE DELETE ON notifications
    FOR EACH ROW EXECUTE FUNCTION enforce_notification_floor();

-- ---- GR-07: category-based routing to a department / officer ---------------
-- A fiduciary may route each complaint category to a named department and the
-- officer who handles it; categories without a rule fall back to the DPO.
CREATE TABLE IF NOT EXISTS grievance_routing_rules (
    fiduciary_id     UUID NOT NULL REFERENCES fiduciaries(id),
    grievance_type   VARCHAR(50) NOT NULL,
    department       VARCHAR(100) NOT NULL,
    operator_id      UUID NOT NULL REFERENCES operators(id),
    updated_by       VARCHAR(255),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (fiduciary_id, grievance_type)
);
ALTER TABLE grievances ADD COLUMN IF NOT EXISTS department VARCHAR(100);
