-- ============================================================================
-- db/34_principal_pii_encryption.sql
--
-- Data Principal identifiers are no longer stored in plaintext. Every column
-- below is replaced by a pair:
--     <col>_enc   encode(pgp_sym_encrypt(trim(v), key), 'base64')   (reveal)
--     <col>_hmac  encode(hmac(trim(v), key, 'sha256'), 'hex')       (lookup)
-- with key = current_setting('app.enc_key'), the same key as DB_ENCRYPTION_KEY
-- and python_port/dpdpcms_py/pii.py (HMAC_SQL / ENC_SQL). trim() strips
-- spaces only and case is preserved, byte for byte what pii.hmac_hex computes.
-- The pair is NOT NULL where the source column was, nullable otherwise.
--
-- INVENTORY (grep -niE "user_id|principal_id|recipient_id|guardian_id|nominee"
-- db/*.sql, plus the live schema):
--   consent_records.user_id
--   data_principal.user_id, data_principal.guardian_id (nullable)
--   grievances.user_id
--   purge_requests.user_id
--   consent_validations.user_id
--   breach_affected_principals.user_id
--   parental_verification_logs.child_principal_id, .guardian_principal_id
--   notifications.recipient_id          (principal id, or a DPO/app id)
--   data_correction_requests.user_id
--   reconsent_requests.user_id
--   notification_deliveries.recipient   (nullable; the resolved address/device
--                                        - the column is named `recipient`)
--   nominations.nominating_principal_id, .nominated_principal_id
--   alerts.recipient_id                 (nullable; principal id for PRINCIPAL
--                                        alerts, else a processor/app id)
--   evidence_certificates.subject_principal_id
-- Excluded: audit_logs.user_id (already security.pseudonym(), feeds the hash
-- chain) and its legacy/partition tables; principal_otps.subject_hash (already
-- an HMAC); auth_throttles.key (already hashed). Principal ids inside JSON
-- payloads (alerts.payload, webhook_deliveries.payload, jobs.input_payload)
-- are not columns and are handled by the services. Migration 35 handles
-- parental_verification_logs evidence and consent_records.ip_address.
--
-- Every index, primary key and unique constraint that used a plaintext column
-- is rebuilt on its _hmac column UNDER THE SAME NAME, so the CREATE ... IF NOT
-- EXISTS statements in db/14, db/15 and db/26 (guarded on the plaintext
-- column) stay re-runnable.
--
-- KEY RULE: if any affected table has rows and app.enc_key is unset, the file
-- RAISEs before changing anything (one transaction). An empty database (CI,
-- which does not run 03z_enc_key.sh) migrates without a key. To migrate data:
--     ALTER DATABASE <db> SET app.enc_key = '<DB_ENCRYPTION_KEY>';  -- new session
--  or SET app.enc_key = '<DB_ENCRYPTION_KEY>'; in the psql session.
-- Losing the key after this runs makes every row unattributable.
--
-- Idempotent: each table is converted only while its plaintext column still
-- exists; a re-run only re-asserts the two trigger functions at the bottom
-- (db/24-27 define their plaintext-era versions, so a re-run of those files
-- must be followed by this one - the upgrade loop always ends here).
-- ============================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TEMP TABLE tsi_pii_targets (tbl TEXT, col TEXT) ON COMMIT DROP;
INSERT INTO tsi_pii_targets VALUES
    ('consent_records', 'user_id'),
    ('data_principal', 'user_id'),
    ('data_principal', 'guardian_id'),
    ('grievances', 'user_id'),
    ('purge_requests', 'user_id'),
    ('consent_validations', 'user_id'),
    ('breach_affected_principals', 'user_id'),
    ('parental_verification_logs', 'child_principal_id'),
    ('parental_verification_logs', 'guardian_principal_id'),
    ('notifications', 'recipient_id'),
    ('data_correction_requests', 'user_id'),
    ('reconsent_requests', 'user_id'),
    ('notification_deliveries', 'recipient'),
    ('nominations', 'nominating_principal_id'),
    ('nominations', 'nominated_principal_id'),
    ('alerts', 'recipient_id'),
    ('evidence_certificates', 'subject_principal_id');

CREATE FUNCTION pg_temp.tsi_pii_pending(t TEXT, c TEXT) RETURNS BOOLEAN AS $$
    SELECT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = t AND column_name = c
    );
$$ LANGUAGE sql;

-- ---- Guard: rows to convert but no key -> stop before anything changes -------
DO $$
DECLARE
    target   RECORD;
    has_rows BOOLEAN;
BEGIN
    IF COALESCE(current_setting('app.enc_key', true), '') <> '' THEN
        RETURN;
    END IF;
    FOR target IN SELECT tbl, col FROM tsi_pii_targets LOOP
        CONTINUE WHEN NOT pg_temp.tsi_pii_pending(target.tbl, target.col);
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM public.%I)', target.tbl) INTO has_rows;
        IF has_rows THEN
            RAISE EXCEPTION 'db/34: % has rows to encrypt but app.enc_key is unset; nothing was changed. Set app.enc_key to DB_ENCRYPTION_KEY and re-run.', target.tbl;
        END IF;
    END LOOP;
END $$;

-- Adds <c>_enc/<c>_hmac and backfills them from <c>; FALSE when <c> is gone
-- (already converted). The plaintext column is dropped by the caller once the
-- table's keys have been moved.
CREATE FUNCTION pg_temp.tsi_pii_encrypt(t TEXT, c TEXT) RETURNS BOOLEAN AS $$
DECLARE
    key      TEXT := NULLIF(current_setting('app.enc_key', true), '');
    nullable BOOLEAN;
    pending  BOOLEAN;
BEGIN
    SELECT is_nullable = 'YES' INTO nullable
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = t AND column_name = c;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    EXECUTE format('ALTER TABLE public.%I ADD COLUMN IF NOT EXISTS %I TEXT, ADD COLUMN IF NOT EXISTS %I TEXT',
                   t, c || '_enc', c || '_hmac');
    -- Re-checked under the ALTER's lock: a row written after the guard ran
    -- must not be dropped unencrypted.
    IF key IS NULL THEN
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM public.%I WHERE %I IS NOT NULL)', t, c) INTO pending;
        IF pending THEN
            RAISE EXCEPTION 'db/34: %.% has rows to encrypt but app.enc_key is unset', t, c;
        END IF;
    END IF;
    EXECUTE format(
        'UPDATE public.%1$I SET %2$I = encode(pgp_sym_encrypt(trim(%4$I), $1), ''base64''),'
        ' %3$I = encode(hmac(trim(%4$I), $1, ''sha256''), ''hex'') WHERE %4$I IS NOT NULL',
        t, c || '_enc', c || '_hmac', c) USING key;
    IF NOT nullable THEN
        EXECUTE format('ALTER TABLE public.%I ALTER COLUMN %I SET NOT NULL, ALTER COLUMN %I SET NOT NULL',
                       t, c || '_enc', c || '_hmac');
    END IF;
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION pg_temp.tsi_pii_drop(t TEXT, c TEXT) RETURNS VOID AS $$
BEGIN
    EXECUTE format('ALTER TABLE public.%I DROP COLUMN IF EXISTS %I', t, c);
END;
$$ LANGUAGE plpgsql;

-- ---- consent_records ---------------------------------------------------------
-- The backfill runs under the maintenance opt-in with the append-only row
-- trigger disabled for this statement only (inside this transaction, under
-- the ALTER's ACCESS EXCLUSIVE lock): the trigger's maintenance branch also
-- re-checks every grant against its expiry, so any row holding a lapsed grant
-- would otherwise abort the migration.
DO $$
BEGIN
    IF pg_temp.tsi_pii_pending('consent_records', 'user_id') THEN
        PERFORM set_config('tsi.consent_maintenance', 'on', true);
        ALTER TABLE consent_records DISABLE TRIGGER trg_consent_records_append_only;
        PERFORM pg_temp.tsi_pii_encrypt('consent_records', 'user_id');
        ALTER TABLE consent_records ENABLE TRIGGER trg_consent_records_append_only;
        PERFORM set_config('tsi.consent_maintenance', '', true);
        DROP INDEX IF EXISTS idx_unique_active_consent;
        DROP INDEX IF EXISTS idx_unique_active_consent_policy;
        DROP INDEX IF EXISTS idx_consent_records_active_lookup;
        DROP INDEX IF EXISTS idx_consent_records_history;
        PERFORM pg_temp.tsi_pii_drop('consent_records', 'user_id');
        CREATE UNIQUE INDEX idx_unique_active_consent_policy
            ON consent_records (user_id_hmac, fiduciary_id, policy_id) WHERE is_active_consent IS TRUE;
        CREATE INDEX idx_consent_records_active_lookup
            ON consent_records (user_id_hmac, fiduciary_id) WHERE (is_active_consent = TRUE);
        CREATE INDEX idx_consent_records_history
            ON consent_records (user_id_hmac, fiduciary_id, timestamp DESC);
    END IF;
END $$;

-- ---- data_principal ----------------------------------------------------------
DO $$
BEGIN
    IF pg_temp.tsi_pii_pending('data_principal', 'user_id') THEN
        PERFORM pg_temp.tsi_pii_encrypt('data_principal', 'user_id');
        ALTER TABLE data_principal DROP CONSTRAINT IF EXISTS data_principal_pkey;
        DROP INDEX IF EXISTS idx_data_principal_auth_link;
        PERFORM pg_temp.tsi_pii_drop('data_principal', 'user_id');
        ALTER TABLE data_principal ADD CONSTRAINT data_principal_pkey PRIMARY KEY (user_id_hmac, fiduciary_id);
        CREATE INDEX idx_data_principal_auth_link
            ON data_principal (user_id_hmac, fiduciary_id, verification_status);
    END IF;
    IF pg_temp.tsi_pii_encrypt('data_principal', 'guardian_id') THEN
        PERFORM pg_temp.tsi_pii_drop('data_principal', 'guardian_id');
    END IF;
END $$;

-- ---- grievances --------------------------------------------------------------
DO $$
BEGIN
    IF pg_temp.tsi_pii_encrypt('grievances', 'user_id') THEN
        DROP INDEX IF EXISTS idx_grievances_fid_user_timestamp;
        PERFORM pg_temp.tsi_pii_drop('grievances', 'user_id');
        CREATE INDEX idx_grievances_fid_user_timestamp
            ON grievances (fiduciary_id, user_id_hmac, submission_timestamp DESC);
    END IF;
END $$;

-- ---- purge_requests ----------------------------------------------------------
DO $$
BEGIN
    IF pg_temp.tsi_pii_encrypt('purge_requests', 'user_id') THEN
        DROP INDEX IF EXISTS idx_purge_requests_user_search;
        PERFORM pg_temp.tsi_pii_drop('purge_requests', 'user_id');
        CREATE INDEX idx_purge_requests_user_search ON purge_requests (user_id_hmac);
    END IF;
END $$;

-- ---- consent_validations (no index used user_id) -----------------------------
DO $$
BEGIN
    IF pg_temp.tsi_pii_encrypt('consent_validations', 'user_id') THEN
        PERFORM pg_temp.tsi_pii_drop('consent_validations', 'user_id');
    END IF;
END $$;

-- ---- breach_affected_principals ----------------------------------------------
DO $$
BEGIN
    IF pg_temp.tsi_pii_encrypt('breach_affected_principals', 'user_id') THEN
        ALTER TABLE breach_affected_principals DROP CONSTRAINT IF EXISTS breach_affected_principals_pkey;
        PERFORM pg_temp.tsi_pii_drop('breach_affected_principals', 'user_id');
        ALTER TABLE breach_affected_principals
            ADD CONSTRAINT breach_affected_principals_pkey PRIMARY KEY (breach_id, user_id_hmac);
    END IF;
END $$;

-- ---- parental_verification_logs ----------------------------------------------
DO $$
DECLARE
    child_done    BOOLEAN;
    guardian_done BOOLEAN;
BEGIN
    child_done := pg_temp.tsi_pii_encrypt('parental_verification_logs', 'child_principal_id');
    guardian_done := pg_temp.tsi_pii_encrypt('parental_verification_logs', 'guardian_principal_id');
    IF child_done OR guardian_done THEN
        DROP INDEX IF EXISTS idx_guardian_child;
        PERFORM pg_temp.tsi_pii_drop('parental_verification_logs', 'child_principal_id');
        PERFORM pg_temp.tsi_pii_drop('parental_verification_logs', 'guardian_principal_id');
        CREATE INDEX idx_guardian_child
            ON parental_verification_logs (guardian_principal_id_hmac, child_principal_id_hmac);
    END IF;
END $$;

-- ---- notifications -----------------------------------------------------------
DO $$
BEGIN
    IF pg_temp.tsi_pii_encrypt('notifications', 'recipient_id') THEN
        DROP INDEX IF EXISTS idx_notifications_recipient_created;
        PERFORM pg_temp.tsi_pii_drop('notifications', 'recipient_id');
        CREATE INDEX idx_notifications_recipient_created
            ON notifications (recipient_id_hmac, created_at DESC);
    END IF;
END $$;

-- ---- data_correction_requests ------------------------------------------------
DO $$
BEGIN
    IF pg_temp.tsi_pii_encrypt('data_correction_requests', 'user_id') THEN
        DROP INDEX IF EXISTS idx_data_correction_fiduciary_user;
        PERFORM pg_temp.tsi_pii_drop('data_correction_requests', 'user_id');
        CREATE INDEX idx_data_correction_fiduciary_user
            ON data_correction_requests (fiduciary_id, user_id_hmac, created_at DESC);
    END IF;
END $$;

-- ---- reconsent_requests ------------------------------------------------------
DO $$
BEGIN
    IF pg_temp.tsi_pii_encrypt('reconsent_requests', 'user_id') THEN
        ALTER TABLE reconsent_requests
            DROP CONSTRAINT IF EXISTS reconsent_requests_fiduciary_id_policy_id_policy_version_us_key;
        PERFORM pg_temp.tsi_pii_drop('reconsent_requests', 'user_id');
        ALTER TABLE reconsent_requests
            ADD CONSTRAINT reconsent_requests_fiduciary_id_policy_id_policy_version_us_key
            UNIQUE (fiduciary_id, policy_id, policy_version, user_id_hmac);
    END IF;
END $$;

-- ---- notification_deliveries (column is `recipient`; no index used it) -------
-- The backfill runs under the plaintext-era UPDATE floor (recipient itself is
-- unchanged); the floor is rewritten for the encrypted pair below.
DO $$
BEGIN
    IF pg_temp.tsi_pii_encrypt('notification_deliveries', 'recipient') THEN
        PERFORM pg_temp.tsi_pii_drop('notification_deliveries', 'recipient');
    END IF;
END $$;

-- ---- nominations -------------------------------------------------------------
DO $$
DECLARE
    nominator_done BOOLEAN;
    nominee_done   BOOLEAN;
BEGIN
    nominator_done := pg_temp.tsi_pii_encrypt('nominations', 'nominating_principal_id');
    nominee_done := pg_temp.tsi_pii_encrypt('nominations', 'nominated_principal_id');
    IF nominator_done OR nominee_done THEN
        DROP INDEX IF EXISTS idx_nominations_fiduciary_nominator;
        PERFORM pg_temp.tsi_pii_drop('nominations', 'nominating_principal_id');
        PERFORM pg_temp.tsi_pii_drop('nominations', 'nominated_principal_id');
        CREATE INDEX idx_nominations_fiduciary_nominator
            ON nominations (fiduciary_id, nominating_principal_id_hmac);
    END IF;
END $$;

-- ---- alerts ------------------------------------------------------------------
DO $$
BEGIN
    IF pg_temp.tsi_pii_encrypt('alerts', 'recipient_id') THEN
        DROP INDEX IF EXISTS idx_alerts_recipient;
        PERFORM pg_temp.tsi_pii_drop('alerts', 'recipient_id');
        CREATE INDEX idx_alerts_recipient ON alerts (fiduciary_id, recipient_id_hmac, created_at DESC);
    END IF;
END $$;

-- ---- evidence_certificates (no index used subject_principal_id) --------------
DO $$
BEGIN
    IF pg_temp.tsi_pii_encrypt('evidence_certificates', 'subject_principal_id') THEN
        PERFORM pg_temp.tsi_pii_drop('evidence_certificates', 'subject_principal_id');
    END IF;
END $$;

-- ---- Trigger functions that named a dropped column ---------------------------
-- db/27's consent_records maintenance guard, with the encrypted pair (which
-- erasure re-keys) in place of the dropped plaintext user_id.
CREATE OR REPLACE FUNCTION consent_records_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND COALESCE(current_setting('tsi.consent_maintenance', true), '') = 'on'
       AND NOT (OLD.is_active_consent IS FALSE AND NEW.is_active_consent IS TRUE)
       AND (to_jsonb(NEW) - 'user_id_enc' - 'user_id_hmac' - 'ip_address' - 'user_agent'
                          - 'data_point_consents' - 'last_updated_at' - 'is_active_consent')
         = (to_jsonb(OLD) - 'user_id_enc' - 'user_id_hmac' - 'ip_address' - 'user_agent'
                          - 'data_point_consents' - 'last_updated_at' - 'is_active_consent')
       -- P11-02: the decisions stay an array; anything else would erase them.
       AND jsonb_typeof(NEW.data_point_consents) = 'array'
       -- P11-01: no purpose granted in NEW that was not granted in OLD, with
       -- "granted" read the way the consent gate reads it. NEW is tested
       -- without expiry (any truthy grant counts), OLD with it (a lapsed grant
       -- does not license a fresh one), so the test only ever errs closed.
       AND NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(NEW.data_point_consents) AS n
            WHERE tsi_point_granted(n, FALSE)
              AND NOT EXISTS (
                    SELECT 1 FROM jsonb_array_elements(
                             CASE WHEN jsonb_typeof(OLD.data_point_consents) = 'array'
                                  THEN OLD.data_point_consents ELSE '[]'::jsonb END) AS o
                    WHERE tsi_point_granted(o, TRUE)
                      AND tsi_point_purpose(o) = tsi_point_purpose(n)
                      AND tsi_point_purpose(n) <> ''
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

-- db/24's notification_deliveries UPDATE floor: inside the one-year floor the
-- encrypted recipient may change only to the erasure placeholder, which is
-- itself encrypted, so it is decrypted here with app.enc_key. A value that
-- does not decrypt (or no key) is not an erasure: the floor errs closed.
CREATE OR REPLACE FUNCTION enforce_notification_delivery_update_floor() RETURNS trigger AS $$
DECLARE
    new_plain TEXT;
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.notification_id IS DISTINCT FROM OLD.notification_id
       OR NEW.channel IS DISTINCT FROM OLD.channel
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'Rule 6(1)(e): notification_deliveries identity columns are immutable';
    END IF;
    IF OLD.created_at > NOW() - INTERVAL '365 days'
       AND (NEW.recipient_enc IS DISTINCT FROM OLD.recipient_enc
            OR NEW.recipient_hmac IS DISTINCT FROM OLD.recipient_hmac) THEN
        BEGIN
            new_plain := pgp_sym_decrypt(decode(NEW.recipient_enc, 'base64'),
                                         current_setting('app.enc_key', true));
        EXCEPTION WHEN others THEN
            new_plain := NULL;
        END;
        IF COALESCE(new_plain, '') NOT LIKE 'erased:%'
           OR NEW.recipient_hmac IS DISTINCT FROM
              encode(hmac(trim(new_plain), current_setting('app.enc_key', true), 'sha256'), 'hex') THEN
            RAISE EXCEPTION 'Rule 6(1)(e): notification_deliveries.recipient may not be altered before the one-year floor except by erasure';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMIT;
