-- ============================================================================
-- db/32_partition_audit_logs.sql
--
-- audit_logs becomes a table range-partitioned by `timestamp`, one partition
-- per calendar year, so old years can be DETACHED into standalone archive
-- tables (jobs.archive_audit_partitions, registry in db/33) instead of the
-- ledger growing without bound. Nothing is ever deleted: an archived year
-- stays queryable and audit.ledger_source() reads across it.
--
-- PRE-PRODUCTION LEDGER RESET (spec decision). The existing table is renamed
-- to audit_logs_legacy_pre32 and its rows are NOT copied: the new ledger's
-- hash chain starts again from genesis. The legacy table keeps its rows,
-- indexes (renamed with a _legacy suffix) and its append-only triggers
-- (P16-02: they were dropped here before), and db/37 seals its row count and
-- chain head for audit.verify_legacy_ledger. Its rows are not copied because
-- they carry raw principal ids in context_details. An operator may export it
-- and, once the Rule 6(1)(e) year has passed, DROP TABLE audit_logs_legacy_pre32
-- (row triggers do not block DROP); see docs/security/LOG_RETENTION.md.
--
-- Postgres requires the partition key in the primary key, so the PK is
-- (id, timestamp). No foreign key or view references audit_logs.
--
-- A DEFAULT partition catches a row dated in a year with no partition yet
-- (e.g. a Dec 31 -> Jan 1 rollover before the worker pre-creates next year),
-- so an insert never fails for want of a partition.
--
-- Idempotent: if audit_logs is already partitioned the whole file is a no-op.
-- One DO block, so a failure part-way leaves the old table untouched.
-- ============================================================================

DO $$
DECLARE
    idx RECORD;
    y INTEGER;
    part TEXT;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_partitioned_table WHERE partrelid = to_regclass('public.audit_logs')) THEN
        RAISE NOTICE 'audit_logs is already partitioned; nothing to do';
        RETURN;
    END IF;

    IF to_regclass('public.audit_logs') IS NOT NULL THEN
        IF to_regclass('public.audit_logs_legacy_pre32') IS NOT NULL THEN
            RAISE EXCEPTION 'audit_logs_legacy_pre32 already exists while audit_logs is not partitioned; resolve by hand';
        END IF;
        ALTER TABLE audit_logs RENAME TO audit_logs_legacy_pre32;
        -- Renaming a table keeps its index names; move them out of the way of
        -- the same-named indexes created below.
        FOR idx IN
            SELECT c.relname FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
            WHERE i.indrelid = 'public.audit_logs_legacy_pre32'::regclass
        LOOP
            EXECUTE format('ALTER INDEX public.%I RENAME TO %I', idx.relname, left(idx.relname, 56) || '_legacy');
        END LOOP;
    END IF;

    -- The exact column list of db/01 + db/02 + db/16.
    CREATE TABLE audit_logs (
        id                UUID NOT NULL DEFAULT uuid_generate_v4(),
        fiduciary_id      UUID,
        timestamp         TIMESTAMP NOT NULL,
        user_id           VARCHAR(255) NOT NULL,
        service_type      VARCHAR(100) NOT NULL,
        service_id        UUID,
        audit_action      VARCHAR(100) NOT NULL,
        context_details   TEXT,
        prev_log_hash     VARCHAR(64),
        current_log_hash  VARCHAR(64),
        digital_signature TEXT,
        system_metadata   JSONB,
        purpose_id        VARCHAR(255),
        consent_status    VARCHAR(50),
        initiator         VARCHAR(255),
        source_ip         VARCHAR(100),
        PRIMARY KEY (id, timestamp)
    ) PARTITION BY RANGE (timestamp);

    FOR y IN 2025 .. EXTRACT(YEAR FROM (now() AT TIME ZONE 'UTC'))::INTEGER + 1 LOOP
        part := 'audit_logs_y' || y;
        EXECUTE format(
            'CREATE TABLE public.%I PARTITION OF audit_logs FOR VALUES FROM (%L) TO (%L)',
            part, make_date(y, 1, 1)::timestamp, make_date(y + 1, 1, 1)::timestamp);
    END LOOP;
    CREATE TABLE audit_logs_default PARTITION OF audit_logs DEFAULT;

    -- Indexes of db/01, db/02, db/24 and db/29; they cascade to every partition.
    CREATE INDEX idx_audit_logs_service_timestamp ON audit_logs (service_type, timestamp DESC);
    CREATE INDEX idx_audit_logs_fid_action_timestamp ON audit_logs (fiduciary_id, audit_action, timestamp DESC);
    CREATE INDEX idx_audit_logs_user_timestamp ON audit_logs (user_id, timestamp DESC);
    CREATE INDEX idx_audit_hash_traversal ON audit_logs (current_log_hash);
    CREATE INDEX idx_audit_principal_trace ON audit_logs (user_id, timestamp DESC);
    CREATE INDEX idx_audit_fiduciary_logs ON audit_logs (fiduciary_id, timestamp DESC);
    CREATE INDEX idx_audit_logs_chain_order ON audit_logs (timestamp DESC, id DESC);
    CREATE INDEX idx_audit_logs_canonical_purpose ON audit_logs (tsi_canonical_purpose(purpose_id));

    -- db/19: append-only. Row triggers on the parent are cloned to every
    -- partition; a statement-level TRUNCATE trigger is not, so each partition
    -- gets its own (TRUNCATE audit_logs_y2026 must fail too).
    CREATE TRIGGER trg_audit_logs_no_update_delete
        BEFORE UPDATE OR DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only();
    CREATE TRIGGER trg_audit_logs_no_truncate
        BEFORE TRUNCATE ON audit_logs
        FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_append_only();
    FOR part IN
        SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = 'public.audit_logs'::regclass
    LOOP
        EXECUTE format(
            'CREATE TRIGGER trg_audit_logs_no_truncate BEFORE TRUNCATE ON public.%I'
            ' FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_append_only()', part);
    END LOOP;

    -- db/28 + db/30: row-level security for tenant readers, on the parent
    -- (queries through audit_logs are filtered; partitions are not granted).
    ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
    CREATE POLICY tsi_unrestricted ON audit_logs
        USING (NOT pg_has_role(current_user, 'tsi_tenant_reader', 'MEMBER'))
        WITH CHECK (NOT pg_has_role(current_user, 'tsi_tenant_reader', 'MEMBER'));
    CREATE POLICY tsi_tenant_isolation ON audit_logs FOR SELECT TO tsi_tenant_reader
        USING (fiduciary_id::text IN (SELECT tenant_id::text FROM tsi_reader_my_tenants));
    GRANT SELECT ON audit_logs TO tsi_tenant_reader;
END;
$$;
