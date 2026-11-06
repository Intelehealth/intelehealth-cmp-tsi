-- ============================================================================
-- db/30_p13_remediation.sql
--
-- Workbook v11 (revision 15) remediation. Idempotent; safe to re-run.
--
--   P13-03 the tenant-reader RLS helper tsi_reader_may_see(role, tenant) was
--          executable by readers and took any role name, so a reader could
--          test whether any role was mapped to any tenant. The policies now
--          consult a security-barrier view that only ever returns the
--          querying role's own mappings, and the helper is dropped.
-- ============================================================================

-- A view (not security_invoker) reads tsi_reader_tenants with its owner's
-- privileges, while current_user inside it is still the querying role, so a
-- reader sees exactly its own rows. security_barrier keeps a reader's own
-- functions from being evaluated against rows the filter removes.
CREATE OR REPLACE VIEW tsi_reader_my_tenants WITH (security_barrier = true) AS
    SELECT tenant_id FROM tsi_reader_tenants WHERE role_name = current_user;
REVOKE ALL ON tsi_reader_my_tenants FROM PUBLIC;
GRANT SELECT ON tsi_reader_my_tenants TO tsi_tenant_reader;

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
        EXECUTE format('DROP POLICY IF EXISTS tsi_tenant_isolation ON public.%I', t.table_name);
        EXECUTE format(
            'CREATE POLICY tsi_tenant_isolation ON public.%I FOR SELECT TO tsi_tenant_reader'
            ' USING (fiduciary_id::text IN (SELECT tenant_id::text FROM tsi_reader_my_tenants))',
            t.table_name);
    END LOOP;
END;
$$;

DROP FUNCTION IF EXISTS tsi_reader_may_see(NAME, TEXT);
