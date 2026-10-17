-- ============================================================================
-- db/35_evidence_ip_encryption.sql
--
-- The last plaintext personal data db/34 left behind:
--   parental_verification_logs.verification_ref_id -> verification_ref_id_enc
--   parental_verification_logs.proof_metadata      -> proof_metadata_enc
--                                   (the JSON document, as text, encrypted)
--   consent_records.ip_address                     -> ip_address_enc NOT NULL
--   consent_records.client_metadata.ip_address     -> client_metadata.ip_address_enc
--                                   (the IP the integrator claimed, inside the JSON)
-- each encode(pgp_sym_encrypt(v, key), 'base64') with key =
-- current_setting('app.enc_key') (= DB_ENCRYPTION_KEY), decrypted with
-- pgp_sym_decrypt(decode(c, 'base64'), key). The values are evidence, not
-- lookup keys: no HMAC, no trim, nothing indexed.
--
-- audit_logs.source_ip widens from VARCHAR(100) to TEXT on the partitioned
-- parent (every live partition follows) and on every detached archive table
-- (audit_logs_y<YYYY>_archive, which no longer inherit from the parent), so
-- audit.log_event can store the client IP as ciphertext. The row hash covers
-- the stored ciphertext. Existing audit rows are NOT re-encrypted: the ledger
-- is append-only and each row's hash covers its stored source_ip, so rows
-- written before this migration keep their plaintext IP.
--
-- KEY RULE (as db/34): if either table has rows to convert and app.enc_key is
-- unset, the file RAISEs before changing anything (one transaction). An empty
-- database (CI, which does not run 03z_enc_key.sh) migrates without a key.
--
-- Idempotent: each column is converted only while its plaintext column still
-- exists; a re-run widens nothing new and only re-asserts the consent_records
-- append-only trigger function at the bottom (db/24-27 and db/34 define its
-- earlier versions, so a re-run of those must be followed by this file - the
-- upgrade loop always ends here). It also (re)defines tsi_audit_source_ip(),
-- which the console audit reads use to show the client IP, and converts any
-- client_metadata still holding a plaintext claimed 'ip_address'.
-- ============================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE FUNCTION pg_temp.tsi_ev_pending(t TEXT, c TEXT) RETURNS BOOLEAN AS $$
    SELECT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = t AND column_name = c
    );
$$ LANGUAGE sql;

-- ---- Guard: rows to convert but no key -> stop before anything changes -------
DO $$
DECLARE
    has_rows BOOLEAN;
BEGIN
    IF COALESCE(current_setting('app.enc_key', true), '') <> '' THEN
        RETURN;
    END IF;
    IF pg_temp.tsi_ev_pending('consent_records', 'ip_address') THEN
        SELECT EXISTS (SELECT 1 FROM consent_records) INTO has_rows;
        IF has_rows THEN
            RAISE EXCEPTION 'db/35: consent_records has rows to encrypt but app.enc_key is unset; nothing was changed. Set app.enc_key to DB_ENCRYPTION_KEY and re-run.';
        END IF;
    END IF;
    IF EXISTS (SELECT 1 FROM consent_records WHERE client_metadata ? 'ip_address') THEN
        RAISE EXCEPTION 'db/35: consent_records.client_metadata has claimed IPs to encrypt but app.enc_key is unset; nothing was changed. Set app.enc_key to DB_ENCRYPTION_KEY and re-run.';
    END IF;
    IF pg_temp.tsi_ev_pending('parental_verification_logs', 'verification_ref_id')
       OR pg_temp.tsi_ev_pending('parental_verification_logs', 'proof_metadata') THEN
        SELECT EXISTS (SELECT 1 FROM parental_verification_logs) INTO has_rows;
        IF has_rows THEN
            RAISE EXCEPTION 'db/35: parental_verification_logs has rows to encrypt but app.enc_key is unset; nothing was changed. Set app.enc_key to DB_ENCRYPTION_KEY and re-run.';
        END IF;
    END IF;
END $$;

-- Adds <c>_enc and backfills it from <c>::text; FALSE when <c> is gone
-- (already converted). The caller drops the plaintext column.
CREATE FUNCTION pg_temp.tsi_ev_encrypt(t TEXT, c TEXT) RETURNS BOOLEAN AS $$
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
    EXECUTE format('ALTER TABLE public.%I ADD COLUMN IF NOT EXISTS %I TEXT', t, c || '_enc');
    -- Re-checked under the ALTER's lock: a row written after the guard ran
    -- must not be dropped unencrypted.
    IF key IS NULL THEN
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM public.%I WHERE %I IS NOT NULL)', t, c) INTO pending;
        IF pending THEN
            RAISE EXCEPTION 'db/35: %.% has rows to encrypt but app.enc_key is unset', t, c;
        END IF;
    END IF;
    EXECUTE format(
        'UPDATE public.%1$I SET %2$I = encode(pgp_sym_encrypt(%3$I::text, $1), ''base64'') WHERE %3$I IS NOT NULL',
        t, c || '_enc', c) USING key;
    IF NOT nullable THEN
        EXECUTE format('ALTER TABLE public.%I ALTER COLUMN %I SET NOT NULL', t, c || '_enc');
    END IF;
    EXECUTE format('ALTER TABLE public.%I DROP COLUMN %I', t, c);
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- ---- parental_verification_logs (no index or trigger used either column) ----
DO $$
BEGIN
    PERFORM pg_temp.tsi_ev_encrypt('parental_verification_logs', 'verification_ref_id');
    PERFORM pg_temp.tsi_ev_encrypt('parental_verification_logs', 'proof_metadata');
END $$;

-- ---- consent_records ---------------------------------------------------------
-- As in db/34: the backfill runs under the maintenance opt-in with the
-- append-only row trigger disabled for this statement only (inside this
-- transaction, under the ALTER's ACCESS EXCLUSIVE lock), because the
-- trigger's maintenance branch re-checks every grant against its expiry and a
-- row holding a lapsed grant would otherwise abort the migration.
DO $$
BEGIN
    IF pg_temp.tsi_ev_pending('consent_records', 'ip_address') THEN
        PERFORM set_config('tsi.consent_maintenance', 'on', true);
        ALTER TABLE consent_records DISABLE TRIGGER trg_consent_records_append_only;
        PERFORM pg_temp.tsi_ev_encrypt('consent_records', 'ip_address');
        ALTER TABLE consent_records ENABLE TRIGGER trg_consent_records_append_only;
        PERFORM set_config('tsi.consent_maintenance', '', true);
    END IF;
END $$;

-- The IP an integrator claimed is kept apart in client_metadata; its plaintext
-- 'ip_address' key becomes 'ip_address_enc' (same pgp/base64 form). Re-runnable:
-- only rows still holding the plaintext key are touched.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM consent_records WHERE client_metadata ? 'ip_address') THEN
        PERFORM set_config('tsi.consent_maintenance', 'on', true);
        ALTER TABLE consent_records DISABLE TRIGGER trg_consent_records_append_only;
        UPDATE consent_records
           SET client_metadata = (client_metadata - 'ip_address')
                   || jsonb_strip_nulls(jsonb_build_object('ip_address_enc',
                          encode(pgp_sym_encrypt(client_metadata->>'ip_address',
                                                 current_setting('app.enc_key')), 'base64')))
         WHERE client_metadata ? 'ip_address';
        ALTER TABLE consent_records ENABLE TRIGGER trg_consent_records_append_only;
        PERFORM set_config('tsi.consent_maintenance', '', true);
    END IF;
END $$;

-- ---- audit_logs.source_ip -> TEXT (parent, partitions, archives) -------------
-- VARCHAR -> TEXT is binary compatible: no table rewrite, no row trigger fires
-- and the stored bytes (and so every row hash) are unchanged.
DO $$
DECLARE
    tbl RECORD;
BEGIN
    FOR tbl IN
        SELECT c.table_name FROM information_schema.columns c
        WHERE c.table_schema = 'public' AND c.column_name = 'source_ip' AND c.data_type <> 'text'
          AND (c.table_name = 'audit_logs' OR c.table_name ~ '^audit_logs_y[0-9]{4}_archive$')
        ORDER BY c.table_name
    LOOP
        EXECUTE format('ALTER TABLE public.%I ALTER COLUMN source_ip TYPE TEXT', tbl.table_name);
    END LOOP;
END $$;

-- ---- tsi_audit_source_ip(source_ip, key) -------------------------------------
-- The readable client IP of one audit row, for the console's audit reads. A
-- row written before this migration holds the plaintext IP, which always has
-- a '.' (IPv4) or ':' (IPv6) and so can never be base64 ciphertext: it is
-- returned as stored. Anything else is decrypted, and a decrypt failure (a
-- wrong or rotated key, corrupt data) raises rather than leaking ciphertext.
-- NULL stays NULL.
CREATE OR REPLACE FUNCTION tsi_audit_source_ip(v TEXT, key TEXT) RETURNS TEXT AS $$
    SELECT CASE
        WHEN v IS NULL THEN NULL
        WHEN v ~ '[.:]' THEN v
        ELSE pgp_sym_decrypt(decode(v, 'base64'), key)
    END;
$$ LANGUAGE sql STABLE;

-- ---- consent_records append-only trigger --------------------------------------
-- db/34's version with the encrypted ip_address_enc in place of the dropped
-- plaintext ip_address: erasure may still replace it (with the encrypted
-- 0.0.0.0) under the maintenance opt-in, and likewise the claimed IP inside
-- client_metadata (its 'ip_address_enc' key, and nothing else in that
-- document); nothing else may.
CREATE OR REPLACE FUNCTION consent_records_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND COALESCE(current_setting('tsi.consent_maintenance', true), '') = 'on'
       AND NOT (OLD.is_active_consent IS FALSE AND NEW.is_active_consent IS TRUE)
       AND (to_jsonb(NEW) - 'user_id_enc' - 'user_id_hmac' - 'ip_address_enc' - 'user_agent'
                          - 'data_point_consents' - 'last_updated_at' - 'is_active_consent'
                          - 'client_metadata')
         = (to_jsonb(OLD) - 'user_id_enc' - 'user_id_hmac' - 'ip_address_enc' - 'user_agent'
                          - 'data_point_consents' - 'last_updated_at' - 'is_active_consent'
                          - 'client_metadata')
       AND (NEW.client_metadata - 'ip_address_enc') IS NOT DISTINCT FROM (OLD.client_metadata - 'ip_address_enc')
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

COMMIT;
