-- ============================================================================
-- db/28_security_coverage.sql
--
-- Security Coverage sheet remediation (workbook v9). Idempotent; safe to re-run.
--
--   S8-6   a breach records when the Data Protection Board was intimated, under
--          what reference and by whom, and when its principals were notified -
--          the 72-hour deadline column alone was a clock nothing could stop.
--   R6-d   the worker records a heartbeat after every cycle, so a stopped worker
--          (retention, escalation and webhook delivery all stop silently with
--          it) is visible on /healthz/worker instead of only in its absence.
--   R6-b   tenancy is enforced in the application; this adds Postgres row-level
--          security as defence in depth for every OTHER database role. A role
--          granted tsi_tenant_reader (an analyst, a BI tool, a read replica
--          user) sees only the rows of the fiduciary named in the session
--          setting tsi.fiduciary_id, and nothing when it is unset. The table
--          owner - the application - bypasses RLS as before, so the API's
--          behaviour is unchanged.
-- ============================================================================

-- ---- S8-6: Board intimation --------------------------------------------------
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS board_notified_at TIMESTAMPTZ;
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS board_reference TEXT;
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS board_notified_by TEXT;
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS principals_notified_at TIMESTAMPTZ;
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS notification_type VARCHAR(100);

-- ---- R6-d: worker heartbeat ------------------------------------------------------
CREATE TABLE IF NOT EXISTS worker_heartbeat (
    worker_name    VARCHAR(64) PRIMARY KEY,
    last_cycle_at  TIMESTAMPTZ NOT NULL,
    poll_seconds   INTEGER NOT NULL,
    failed_sweeps  JSONB NOT NULL DEFAULT '[]'::jsonb
);

-- ---- R6-b: row-level security for non-application roles ------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tsi_tenant_reader') THEN
        CREATE ROLE tsi_tenant_reader NOLOGIN;
    END IF;
END;
$$;

DO $$
DECLARE
    t RECORD;
BEGIN
    FOR t IN
        SELECT c.table_name
        FROM information_schema.columns c
        JOIN information_schema.tables tb
          ON tb.table_schema = c.table_schema AND tb.table_name = c.table_name AND tb.table_type = 'BASE TABLE'
        WHERE c.table_schema = 'public' AND c.column_name = 'fiduciary_id'
    LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t.table_name);
        -- Every role other than a tenant reader keeps full access, so a
        -- deployment that runs the API as a non-owner role is not broken.
        EXECUTE format('DROP POLICY IF EXISTS tsi_unrestricted ON public.%I', t.table_name);
        EXECUTE format(
            'CREATE POLICY tsi_unrestricted ON public.%I USING (NOT pg_has_role(current_user, ''tsi_tenant_reader'', ''MEMBER''))'
            ' WITH CHECK (NOT pg_has_role(current_user, ''tsi_tenant_reader'', ''MEMBER''))',
            t.table_name);
        -- A tenant reader sees one fiduciary, and writes nothing.
        EXECUTE format('DROP POLICY IF EXISTS tsi_tenant_isolation ON public.%I', t.table_name);
        EXECUTE format(
            'CREATE POLICY tsi_tenant_isolation ON public.%I FOR SELECT TO tsi_tenant_reader'
            ' USING (fiduciary_id::text = NULLIF(current_setting(''tsi.fiduciary_id'', true), ''''))',
            t.table_name);
        EXECUTE format('GRANT SELECT ON public.%I TO tsi_tenant_reader', t.table_name);
    END LOOP;
END;
$$;
