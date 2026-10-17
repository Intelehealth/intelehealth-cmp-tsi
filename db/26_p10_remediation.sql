-- ============================================================================
-- db/26_p10_remediation.sql
--
-- Workbook v8 remediation. Idempotent; safe to re-run.
--
--   P10-04 / P10-05 / P10-09  purpose ids are canonical (trimmed, lower-case)
--          wherever they are stored as keys: the lifecycle, purge requests,
--          retention policies, the ROPA link and consent validations. Existing
--          rows are rewritten once; a BEFORE trigger canonicalises every later
--          write, so the consent gate, the lifecycle, the retention clock and
--          the legal hold can never again disagree about which purpose a
--          string names. Case-variant lifecycle rows are merged, keeping the
--          CLOSED one (fail closed).
--   P10-11 the service keeps one active consent record per principal PER
--          POLICY (CW-03/UD-05); the unique index now says the same, so a
--          principal consenting under a second policy no longer gets a 500.
--   CW-08  per-processor webhook endpoints, and webhook_deliveries.app_id so
--          a withdrawal fans out to each linked processor's own endpoint.
--   NT-02  templates the console saved under names the engine never looked
--          up are merged into the names the services write.
--   P9-05  (residual) the consent_records maintenance opt-in no longer
--          permits DELETE, and cannot turn a purpose from refused to granted,
--          revive a retired record, or change what notice a record cites.
-- ============================================================================

-- ---- P10-04: canonical purpose ids -------------------------------------------
CREATE OR REPLACE FUNCTION tsi_canonical_purpose(value TEXT) RETURNS TEXT AS $$
    SELECT CASE WHEN value IS NULL THEN NULL
                WHEN btrim(value) = 'ALL' THEN 'ALL'
                ELSE lower(btrim(value)) END;
$$ LANGUAGE sql IMMUTABLE;

CREATE OR REPLACE FUNCTION tsi_canonical_purpose_array(value JSONB) RETURNS JSONB AS $$
    SELECT CASE WHEN value IS NULL OR jsonb_typeof(value) <> 'array' THEN value
                ELSE COALESCE((
                    SELECT jsonb_agg(DISTINCT tsi_canonical_purpose(e))
                    FROM jsonb_array_elements_text(value) AS e
                    WHERE btrim(e) <> ''
                ), '[]'::jsonb) END;
$$ LANGUAGE sql IMMUTABLE;

-- Merge case-variant lifecycle rows before canonicalising the key.
DELETE FROM purpose_lifecycle p
USING (
    SELECT ctid, row_number() OVER (
        PARTITION BY fiduciary_id, tsi_canonical_purpose(purpose_id)
        ORDER BY (state = 'CLOSED') DESC, last_updated_at DESC
    ) AS rn
    FROM purpose_lifecycle
) r
WHERE p.ctid = r.ctid AND r.rn > 1;

UPDATE purpose_lifecycle SET purpose_id = tsi_canonical_purpose(purpose_id)
WHERE purpose_id IS DISTINCT FROM tsi_canonical_purpose(purpose_id);
UPDATE purge_requests SET purpose_id = tsi_canonical_purpose(purpose_id)
WHERE purpose_id IS DISTINCT FROM tsi_canonical_purpose(purpose_id);
UPDATE retention_policies SET applicable_purposes = tsi_canonical_purpose_array(applicable_purposes)
WHERE applicable_purposes IS DISTINCT FROM tsi_canonical_purpose_array(applicable_purposes);
UPDATE ropa_entries SET source_purpose_id = tsi_canonical_purpose(source_purpose_id)
WHERE source_purpose_id IS DISTINCT FROM tsi_canonical_purpose(source_purpose_id);
UPDATE consent_validations SET purpose_id = tsi_canonical_purpose(purpose_id)
WHERE purpose_id IS DISTINCT FROM tsi_canonical_purpose(purpose_id);

CREATE OR REPLACE FUNCTION tsi_canonicalise_purpose_id() RETURNS trigger AS $$
BEGIN
    NEW.purpose_id := tsi_canonical_purpose(NEW.purpose_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION tsi_canonicalise_source_purpose_id() RETURNS trigger AS $$
BEGIN
    NEW.source_purpose_id := tsi_canonical_purpose(NEW.source_purpose_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION tsi_canonicalise_applicable_purposes() RETURNS trigger AS $$
BEGIN
    NEW.applicable_purposes := tsi_canonical_purpose_array(NEW.applicable_purposes);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_purpose_lifecycle_canonical ON purpose_lifecycle;
CREATE TRIGGER trg_purpose_lifecycle_canonical
    BEFORE INSERT OR UPDATE OF purpose_id ON purpose_lifecycle
    FOR EACH ROW EXECUTE FUNCTION tsi_canonicalise_purpose_id();

DROP TRIGGER IF EXISTS trg_purge_requests_canonical ON purge_requests;
CREATE TRIGGER trg_purge_requests_canonical
    BEFORE INSERT OR UPDATE OF purpose_id ON purge_requests
    FOR EACH ROW EXECUTE FUNCTION tsi_canonicalise_purpose_id();

DROP TRIGGER IF EXISTS trg_consent_validations_canonical ON consent_validations;
CREATE TRIGGER trg_consent_validations_canonical
    BEFORE INSERT OR UPDATE OF purpose_id ON consent_validations
    FOR EACH ROW EXECUTE FUNCTION tsi_canonicalise_purpose_id();

DROP TRIGGER IF EXISTS trg_ropa_entries_canonical ON ropa_entries;
CREATE TRIGGER trg_ropa_entries_canonical
    BEFORE INSERT OR UPDATE OF source_purpose_id ON ropa_entries
    FOR EACH ROW EXECUTE FUNCTION tsi_canonicalise_source_purpose_id();

DROP TRIGGER IF EXISTS trg_retention_policies_canonical ON retention_policies;
CREATE TRIGGER trg_retention_policies_canonical
    BEFORE INSERT OR UPDATE OF applicable_purposes ON retention_policies
    FOR EACH ROW EXECUTE FUNCTION tsi_canonicalise_applicable_purposes();

-- ---- P10-11: one active record per principal per POLICY ------------------------
DROP INDEX IF EXISTS idx_unique_active_consent;
-- db/34 replaces consent_records.user_id with user_id_hmac and rebuilds this index under
-- the same name; skip once the plaintext column is gone so this file stays re-runnable.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'consent_records' AND column_name = 'user_id') THEN
        CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_active_consent_policy
            ON consent_records (user_id, fiduciary_id, policy_id) WHERE is_active_consent IS TRUE;
    END IF;
END $$;

-- ---- CW-08: per-processor webhook endpoints ----------------------------------
CREATE TABLE IF NOT EXISTS processor_webhook_configs (
    app_id          UUID NOT NULL REFERENCES apps(id),
    fiduciary_id    UUID NOT NULL REFERENCES fiduciaries(id),
    category        VARCHAR(20) NOT NULL,   -- 'NOTIFICATION' or 'PURGE'
    webhook_url     TEXT NOT NULL,
    secret_enc      TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    last_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (app_id, category)
);
CREATE INDEX IF NOT EXISTS idx_processor_webhook_configs_fid
    ON processor_webhook_configs (fiduciary_id, category);

-- NULL = the fiduciary's own endpoint(s); set = that processor's endpoint.
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS app_id UUID REFERENCES apps(id);

CREATE OR REPLACE FUNCTION enforce_webhook_delivery_update_floor() RETURNS trigger AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.fiduciary_id IS DISTINCT FROM OLD.fiduciary_id
       OR NEW.app_id IS DISTINCT FROM OLD.app_id
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

-- ---- NT-02: legacy console template names -> the names the services write ---------
-- A DPO's text overrides the seeded default; the legacy row is then removed so
-- the console shows one card per real notice. PURGE_ONHOLD_NOTIFICATION and
-- EXPIRY_NOTIFICATION have no live counterpart, so any text saved under them
-- is kept as written rather than discarded.
WITH legacy(old_type, new_type) AS (
    VALUES ('GRIEVANCE_SUBMITTED_NOTIFICATION', 'GRIEVANCE_SUBMITTED'),
           ('GRIEVANCE_RESOLVED_NOTIFICATION', 'GRIEVANCE_RESOLVED'),
           ('GRIEVANCE_ESCALATED_NOTIFICATION', 'GRIEVANCE_ESCALATED'),
           ('PURGE_INIT_NOTIFICATION', 'PURGE_SCHEDULED'),
           ('PURGE_CONFIRM_NOTIFICATION', 'PURGE_EXECUTED')
)
INSERT INTO notification_message_templates (fiduciary_id, notification_type, messages, last_updated_at)
SELECT t.fiduciary_id, l.new_type, t.messages, NOW()
FROM notification_message_templates t JOIN legacy l ON l.old_type = t.notification_type
WHERE jsonb_typeof(t.messages) = 'object' AND t.messages <> '{}'::jsonb
ON CONFLICT (fiduciary_id, notification_type) DO UPDATE SET
    messages = notification_message_templates.messages || EXCLUDED.messages,
    last_updated_at = NOW();

DELETE FROM notification_message_templates
WHERE notification_type IN (
    'GRIEVANCE_SUBMITTED_NOTIFICATION', 'GRIEVANCE_RESOLVED_NOTIFICATION', 'GRIEVANCE_ESCALATED_NOTIFICATION',
    'PURGE_INIT_NOTIFICATION', 'PURGE_CONFIRM_NOTIFICATION'
);

-- ---- P9-05 residual: a narrower maintenance opt-in ---------------------------------
-- Maintenance (erasure re-key, metadata scrub, purpose de-identification, the
-- anonymous -> authenticated link) only ever rewrites who a record names, the
-- session metadata and the purpose entries. It never needs to delete a row,
-- revive a retired one, change the notice it cites or its timing, or grant a
-- purpose the principal did not grant - so the opt-in no longer allows any of
-- those, even to a caller holding the application's database credentials.
CREATE OR REPLACE FUNCTION consent_records_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND COALESCE(current_setting('tsi.consent_maintenance', true), '') = 'on'
       AND NOT (OLD.is_active_consent IS FALSE AND NEW.is_active_consent IS TRUE)
       AND (to_jsonb(NEW) - 'user_id' - 'ip_address' - 'user_agent' - 'data_point_consents'
                          - 'last_updated_at' - 'is_active_consent')
         = (to_jsonb(OLD) - 'user_id' - 'ip_address' - 'user_agent' - 'data_point_consents'
                          - 'last_updated_at' - 'is_active_consent')
       AND NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(
                     CASE WHEN jsonb_typeof(NEW.data_point_consents) = 'array'
                          THEN NEW.data_point_consents ELSE '[]'::jsonb END) AS n
            WHERE (n ->> 'consent_granted' = 'true' OR lower(n ->> 'status') IN ('granted', 'consent_given'))
              AND NOT EXISTS (
                    SELECT 1 FROM jsonb_array_elements(
                             CASE WHEN jsonb_typeof(OLD.data_point_consents) = 'array'
                                  THEN OLD.data_point_consents ELSE '[]'::jsonb END) AS o
                    WHERE (o ->> 'consent_granted' = 'true' OR lower(o ->> 'status') IN ('granted', 'consent_given'))
                      AND lower(btrim(COALESCE(o ->> 'data_point_id', o ->> 'purpose_id', o ->> 'id')))
                        = lower(btrim(COALESCE(n ->> 'data_point_id', n ->> 'purpose_id', n ->> 'id')))
                  )
       ) THEN
        RETURN NEW;
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
