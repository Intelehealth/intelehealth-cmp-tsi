-- ============================================================================
-- db/33_audit_archive_registry.sql
--
-- Which yearly audit_logs partitions (db/32) have been detached into
-- standalone archive tables by jobs.archive_audit_partitions. Archives are
-- never dropped; audit.ledger_source() reads this registry to search, verify
-- and certify across the live/archive boundary. Idempotent.
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_log_archive_registry (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    partition_name VARCHAR(100) UNIQUE NOT NULL, -- the archive table, e.g. audit_logs_y2024_archive
    period_start   TIMESTAMP NOT NULL,
    period_end     TIMESTAMP NOT NULL,
    archived_at    TIMESTAMPTZ DEFAULT NOW(),
    row_count      INTEGER
);
