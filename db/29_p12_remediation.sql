-- ============================================================================
-- db/29_p12_remediation.sql
--
-- Workbook v10 (revision 14) remediation. Idempotent; safe to re-run.
--
--   P12-04 the Board intimation is recorded at server time. A time the DPO
--          asserts (an intimation made earlier through another channel) is
--          kept in its own column, and the Rule 7(1) intimation contents and
--          the Rule 7(2)(b) detailed report have somewhere to live.
--   P12-05 row-level security for tsi_tenant_reader no longer trusts a
--          session setting the reader controls. A reader sees the tenants an
--          application-owned table maps its role to, and nothing else.
--   P12-06 consent_policies is keyed per tenant (fiduciary_id, id, version),
--          so one tenant's policy ids neither block nor reveal another's.
--   P12-07 the languages db/27 copied from a legacy template into a live one
--          (text written for a different event) are taken back out, where the
--          DPO has not since edited them. The legacy text stays archived.
--   R6-a   the clear-text contact columns kept beside the encrypted copies
--          are cleared and no longer written.
--   LG-05  expression index for the audit purpose filter.
-- ============================================================================

-- ---- P12-04: Board intimation and Rule 7 contents ----------------------------------
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS board_intimated_at_asserted TIMESTAMPTZ;
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS likely_consequences TEXT;
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS mitigation_measures TEXT;
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS contact_point TEXT;
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS circumstances TEXT;
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS cause_findings TEXT;
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS remedial_measures TEXT;
ALTER TABLE breach_incidents ADD COLUMN IF NOT EXISTS board_report_submitted_at TIMESTAMPTZ;

-- ---- P12-05: tenant readers mapped by the application, not by themselves ---------
-- Owned by the application role; tsi_tenant_reader is granted nothing on it, so
-- a reader can neither read nor change its own mapping. The column is named
-- tenant_id (not fiduciary_id) so db/28's loop never opens it to readers.
CREATE TABLE IF NOT EXISTS tsi_reader_tenants (
    role_name  NAME NOT NULL,
    tenant_id  UUID NOT NULL REFERENCES fiduciaries(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_name, tenant_id)
);
REVOKE ALL ON tsi_reader_tenants FROM PUBLIC;
REVOKE ALL ON tsi_reader_tenants FROM tsi_tenant_reader;

-- SECURITY DEFINER so the policy can consult the mapping the reader may not
-- read. The reader's identity is passed in from the policy (current_user there
-- is the querying role; inside this function it would be the owner).
CREATE OR REPLACE FUNCTION tsi_reader_may_see(p_role NAME, p_fiduciary_id TEXT) RETURNS BOOLEAN
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT EXISTS (
        SELECT 1 FROM tsi_reader_tenants r
        WHERE r.role_name = p_role AND r.tenant_id::text = p_fiduciary_id
    );
$$;
REVOKE ALL ON FUNCTION tsi_reader_may_see(NAME, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tsi_reader_may_see(NAME, TEXT) TO tsi_tenant_reader;

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
            ' USING (tsi_reader_may_see(current_user, fiduciary_id::text))',
            t.table_name);
    END LOOP;
END;
$$;

-- ---- P12-06: consent_policies keyed per tenant ----------------------------------
DO $$
DECLARE
    fk RECORD;
BEGIN
    -- Drop any foreign key that still points at the global (id, version) key.
    FOR fk IN
        SELECT con.conname, rel.relname
        FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        WHERE con.contype = 'f' AND con.confrelid = 'public.consent_policies'::regclass
          AND con.conname <> 'consent_records_policy_tenant_fk'
    LOOP
        EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT %I', fk.relname, fk.conname);
    END LOOP;

    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'public.consent_policies'::regclass AND contype = 'p'
          AND pg_get_constraintdef(oid) <> 'PRIMARY KEY (fiduciary_id, id, version)'
    ) THEN
        EXECUTE (
            SELECT format('ALTER TABLE consent_policies DROP CONSTRAINT %I', conname)
            FROM pg_constraint WHERE conrelid = 'public.consent_policies'::regclass AND contype = 'p'
        );
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conrelid = 'public.consent_policies'::regclass AND contype = 'p'
    ) THEN
        ALTER TABLE consent_policies ADD CONSTRAINT consent_policies_pkey PRIMARY KEY (fiduciary_id, id, version);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'consent_records_policy_tenant_fk'
    ) THEN
        -- NOT VALID: existing rows are checked by the VALIDATE below, which is
        -- reported rather than fatal so an upgrade is never blocked by history.
        ALTER TABLE consent_records ADD CONSTRAINT consent_records_policy_tenant_fk
            FOREIGN KEY (fiduciary_id, policy_id, policy_version)
            REFERENCES consent_policies (fiduciary_id, id, version) NOT VALID;
        BEGIN
            ALTER TABLE consent_records VALIDATE CONSTRAINT consent_records_policy_tenant_fk;
        EXCEPTION WHEN foreign_key_violation THEN
            RAISE WARNING 'consent_records holds rows whose policy belongs to another tenant; '
                          'consent_records_policy_tenant_fk is left NOT VALID for review.';
        END;
    END IF;
END;
$$;

-- ---- P12-07: take back the languages db/27 filled from legacy text ---------------
-- A live language is removed only where it is still byte-for-byte the archived
-- legacy text, i.e. the DPO has not written their own since. The engine then
-- falls back to the default text for that language, as it did before db/27.
UPDATE notification_message_templates t
SET messages = (
        SELECT COALESCE(jsonb_object_agg(e.key, e.value), '{}'::jsonb)
        FROM jsonb_each(t.messages) e
        WHERE NOT (a.messages ? e.key AND a.messages -> e.key = e.value)
    ),
    last_updated_at = NOW()
FROM notification_message_templates_archive a
WHERE a.fiduciary_id = t.fiduciary_id
  AND a.migrated_to = t.notification_type
  AND jsonb_typeof(t.messages) = 'object'
  AND jsonb_typeof(a.messages) = 'object'
  AND EXISTS (
      SELECT 1 FROM jsonb_each(t.messages) e
      WHERE a.messages ? e.key AND a.messages -> e.key = e.value
  );

DELETE FROM notification_message_templates t
WHERE t.messages = '{}'::jsonb
  AND EXISTS (
      SELECT 1 FROM notification_message_templates_archive a
      WHERE a.fiduciary_id = t.fiduciary_id AND a.migrated_to = t.notification_type
  );

-- ---- R6-a: contact details are kept encrypted only ---------------------------------
-- db/04 renamed the clear-text columns to *_plaintext "for rollback" beside the
-- encrypted copies. The application no longer writes them; a value is cleared
-- once its encrypted copy exists.
ALTER TABLE operators ALTER COLUMN email_plaintext DROP NOT NULL;
UPDATE operators SET email_plaintext = NULL WHERE email_plaintext IS NOT NULL AND email_enc IS NOT NULL;
UPDATE fiduciaries SET email_plaintext = NULL WHERE email_plaintext IS NOT NULL AND email_enc IS NOT NULL;
UPDATE fiduciaries SET phone_plaintext = NULL WHERE phone_plaintext IS NOT NULL AND phone_enc IS NOT NULL;
UPDATE apps SET email_plaintext = NULL WHERE email_plaintext IS NOT NULL AND email_enc IS NOT NULL;
UPDATE apps SET phone_plaintext = NULL WHERE phone_plaintext IS NOT NULL AND phone_enc IS NOT NULL;

-- ---- LG-05: the audit purpose filter compares canonical ids --------------------------
CREATE INDEX IF NOT EXISTS idx_audit_logs_canonical_purpose
    ON audit_logs (tsi_canonical_purpose(purpose_id));
