-- ============================================================================
-- db/25_p9_remediation.sql
--
-- Workbook v7 remediation. Idempotent; safe to re-run.
--
--   P9-05  consent_records is append-only at the database level, like
--          audit_logs (db/19) and the delivery tables (db/23, db/24). The API
--          already retires a record and inserts a successor; this makes a raw
--          UPDATE / DELETE / TRUNCATE fail too. Two UPDATE shapes stay legal:
--            * the retirement flip: is_active_consent TRUE -> FALSE, with only
--              last_updated_at changing alongside it;
--            * sanctioned maintenance (erasure re-key to the 'erased:' pseudonym,
--              session-metadata scrub, purpose de-identification, anonymous ->
--              authenticated link), which the service opts into for ONE
--              transaction with set_config('tsi.consent_maintenance', 'on', true).
--   P9-04  purge_requests gains a CANCELLED status: reopening a purpose cancels
--          the erasure purges its closure raised, so no processor acts on them.
-- ============================================================================

-- ---- P9-05: consent_records append-only guard --------------------------------
CREATE OR REPLACE FUNCTION consent_records_append_only() RETURNS trigger AS $$
BEGIN
    IF COALESCE(current_setting('tsi.consent_maintenance', true), '') = 'on' THEN
        IF TG_OP = 'UPDATE' THEN
            RETURN NEW;
        END IF;
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
    END IF;
    IF TG_OP = 'UPDATE'
       AND OLD.is_active_consent IS TRUE
       AND NEW.is_active_consent IS FALSE
       AND (to_jsonb(NEW) - 'is_active_consent' - 'last_updated_at')
         = (to_jsonb(OLD) - 'is_active_consent' - 'last_updated_at') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'consent_records is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_consent_records_append_only ON consent_records;
CREATE TRIGGER trg_consent_records_append_only
    BEFORE UPDATE OR DELETE ON consent_records
    FOR EACH ROW EXECUTE FUNCTION consent_records_append_only();

DROP TRIGGER IF EXISTS trg_consent_records_no_truncate ON consent_records;
CREATE TRIGGER trg_consent_records_no_truncate
    BEFORE TRUNCATE ON consent_records
    FOR EACH STATEMENT EXECUTE FUNCTION consent_records_append_only();

-- ---- P9-04: CANCELLED purge status -------------------------------------------
ALTER TABLE purge_requests DROP CONSTRAINT IF EXISTS chk_purge_requests_status;
ALTER TABLE purge_requests ADD CONSTRAINT chk_purge_requests_status CHECK (status IN (
    'PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'UNDER_LEGAL_HOLD',
    'PURGE_IN_PROGRESS', 'PURGE_COMPLETED', 'PURGE_FAILED', 'LEGAL_HOLD_APPLIED',
    'CANCELLED'
)) NOT VALID;

-- ---- GR-03: the principal's language travels with the grievance --------------
ALTER TABLE grievances ADD COLUMN IF NOT EXISTS language VARCHAR(16);
