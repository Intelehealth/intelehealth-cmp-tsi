-- ============================================================================
-- db/37_p16_remediation.sql
--
-- Workbook revision 17 remediation. Idempotent; safe to re-run.
--
--   P16-02  db/32 renamed the pre-partition ledger to audit_logs_legacy_pre32
--           and dropped its append-only triggers, so the year of logs it holds
--           (Rule 6(1)(e)) was editable. The triggers are put back, and the
--           table's row count and chain head are sealed in
--           audit_legacy_ledger_seal so the worker (audit.verify_legacy_ledger)
--           can recompute the chain against them and record the verdict. The
--           rows are not copied into the live ledger: they carry raw principal
--           ids in context_details, which the live ledger must not.
--   P16-03  alerts.payload and webhook_deliveries.payload hold a principal id
--           only sealed: <key>_enc (ciphertext) and <key>_hmac (lookup HMAC).
--           The Rule 6(1)(e) payload floor on webhook_deliveries now accepts
--           exactly two in-place changes to a principal key, at any depth:
--           erasure (the value becomes an 'erased:' token) and sealing (the
--           same value, now encrypted); a sealed value must carry its HMAC.
--   P16-04  Principal lookup HMACs are keyed by PII_LOOKUP_KEY, which the
--           application sets as app.lookup_key (falling back to app.enc_key
--           where a deployment has not separated them). The notification
--           delivery floor checks a recipient HMAC with it, and accepts a
--           re-key that leaves the encrypted recipient unchanged, so
--           scripts/rekey_pii_lookup.py can move an existing database across.
-- ============================================================================

BEGIN;

-- ---- shared helpers ----------------------------------------------------------

-- The key a principal lookup HMAC is computed with (P16-04).
CREATE OR REPLACE FUNCTION tsi_lookup_key() RETURNS TEXT AS $$
    SELECT COALESCE(NULLIF(current_setting('app.lookup_key', true), ''), current_setting('app.enc_key', true));
$$ LANGUAGE sql STABLE;

-- pii.PRINCIPAL_KEYS: the JSON keys that name a principal. The test suite
-- asserts the two lists are equal.
CREATE OR REPLACE FUNCTION tsi_principal_keys() RETURNS TEXT[] AS $$
    SELECT ARRAY['user_id', 'principal_id', 'guardian_id', 'recipient_id', 'child_principal_id',
                 'guardian_principal_id', 'subject_principal_id', 'nominating_principal_id',
                 'nominated_principal_id', 'nominee_id']::TEXT[];
$$ LANGUAGE sql IMMUTABLE;

CREATE OR REPLACE FUNCTION tsi_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: % is not permitted', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

-- ---- P16-02: the pre-db/32 ledger stays append-only and sealed ---------------

CREATE TABLE IF NOT EXISTS audit_legacy_ledger_seal (
    table_name     VARCHAR(100) PRIMARY KEY,
    row_count      BIGINT NOT NULL,
    head_hash      VARCHAR(64),
    head_timestamp TIMESTAMP,
    sealed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_legacy_ledger_verifications (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    table_name   VARCHAR(100) NOT NULL,
    verified_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    intact       BOOLEAN NOT NULL,
    rows_checked BIGINT NOT NULL,
    result       JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_legacy_ledger_verifications_at
    ON audit_legacy_ledger_verifications (table_name, verified_at DESC);

DROP TRIGGER IF EXISTS trg_audit_legacy_ledger_seal_append_only ON audit_legacy_ledger_seal;
CREATE TRIGGER trg_audit_legacy_ledger_seal_append_only
    BEFORE UPDATE OR DELETE ON audit_legacy_ledger_seal
    FOR EACH ROW EXECUTE FUNCTION tsi_append_only();
DROP TRIGGER IF EXISTS trg_audit_legacy_ledger_verifications_append_only ON audit_legacy_ledger_verifications;
CREATE TRIGGER trg_audit_legacy_ledger_verifications_append_only
    BEFORE UPDATE OR DELETE ON audit_legacy_ledger_verifications
    FOR EACH ROW EXECUTE FUNCTION tsi_append_only();

DO $$
BEGIN
    IF to_regclass('public.audit_logs_legacy_pre32') IS NULL THEN
        RETURN;
    END IF;
    DROP TRIGGER IF EXISTS trg_audit_logs_no_update_delete ON audit_logs_legacy_pre32;
    CREATE TRIGGER trg_audit_logs_no_update_delete
        BEFORE UPDATE OR DELETE ON audit_logs_legacy_pre32
        FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only();
    DROP TRIGGER IF EXISTS trg_audit_logs_no_truncate ON audit_logs_legacy_pre32;
    CREATE TRIGGER trg_audit_logs_no_truncate
        BEFORE TRUNCATE ON audit_logs_legacy_pre32
        FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_append_only();
    -- Its rows name principals in the clear: no tenant reader reads it.
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tsi_tenant_reader') THEN
        REVOKE ALL ON audit_logs_legacy_pre32 FROM tsi_tenant_reader;
    END IF;
    INSERT INTO audit_legacy_ledger_seal (table_name, row_count, head_hash, head_timestamp)
    SELECT 'audit_logs_legacy_pre32',
           (SELECT count(*) FROM audit_logs_legacy_pre32),
           head.current_log_hash,
           head.timestamp
    FROM (SELECT NULL) AS one
    LEFT JOIN LATERAL (
        SELECT current_log_hash, timestamp FROM audit_logs_legacy_pre32
        ORDER BY timestamp DESC, id DESC LIMIT 1
    ) AS head ON TRUE
    ON CONFLICT (table_name) DO NOTHING;
END $$;

-- ---- P16-03: sealed principal keys in queued payloads -------------------------

-- The plaintext a principal key holds in one JSON object: the decrypted
-- <key>_enc when sealed, else the
-- plain <key> value (a non-string as its JSON text); NULL when absent. Raises
-- when a sealed value does not decrypt, or - with check_hmac - when its HMAC
-- does not match it under the current lookup key (the stored side may predate
-- a re-key, so only the new side is checked).
DROP FUNCTION IF EXISTS tsi_payload_principal(JSONB, TEXT);
CREATE OR REPLACE FUNCTION tsi_payload_principal(obj JSONB, k TEXT, check_hmac BOOLEAN) RETURNS TEXT AS $$
DECLARE
    plain TEXT;
BEGIN
    IF obj ? (k || '_enc') THEN
        plain := pgp_sym_decrypt(decode(obj ->> (k || '_enc'), 'base64'), current_setting('app.enc_key', true));
        IF check_hmac AND obj ->> (k || '_hmac') IS DISTINCT FROM encode(hmac(trim(plain), tsi_lookup_key(), 'sha256'), 'hex') THEN
            RAISE EXCEPTION 'sealed % carries no matching HMAC', k;
        END IF;
        RETURN plain;
    END IF;
    IF obj ? k AND jsonb_typeof(obj -> k) = 'string' THEN
        RETURN obj ->> k;
    END IF;
    RETURN (obj -> k)::TEXT;
END;
$$ LANGUAGE plpgsql STABLE;

-- True when new_p differs from old_p only in principal keys, and each changed
-- principal value is an erasure token or the same value sealed.
CREATE OR REPLACE FUNCTION tsi_payload_change_ok(old_p JSONB, new_p JSONB) RETURNS BOOLEAN AS $$
DECLARE
    keys TEXT[] := tsi_principal_keys();
    k TEXT;
    base TEXT;
    old_v TEXT;
    new_v TEXT;
    i INTEGER;
BEGIN
    IF jsonb_typeof(old_p) = 'object' AND jsonb_typeof(new_p) = 'object' THEN
        FOR k IN SELECT key FROM jsonb_object_keys(old_p) AS key UNION SELECT key FROM jsonb_object_keys(new_p) AS key LOOP
            base := regexp_replace(k, '_(enc|hmac|json)$', '');
            IF base <> k AND base = ANY (keys) THEN
                CONTINUE;  -- a sealed companion: judged with its principal key below
            END IF;
            IF k = ANY (keys) THEN
                CONTINUE;
            END IF;
            IF NOT tsi_payload_change_ok(old_p -> k, new_p -> k) THEN
                RETURN FALSE;
            END IF;
        END LOOP;
        FOREACH k IN ARRAY keys LOOP
            IF NOT (old_p ? k OR old_p ? (k || '_enc') OR new_p ? k OR new_p ? (k || '_enc')) THEN
                CONTINUE;
            END IF;
            BEGIN
                old_v := tsi_payload_principal(old_p, k, FALSE);
                new_v := tsi_payload_principal(new_p, k, TRUE);
            EXCEPTION WHEN others THEN
                RETURN FALSE;
            END;
            IF new_v IS DISTINCT FROM old_v AND COALESCE(new_v, '') NOT LIKE 'erased:%' THEN
                RETURN FALSE;
            END IF;
        END LOOP;
        RETURN TRUE;
    END IF;
    IF jsonb_typeof(old_p) = 'array' AND jsonb_typeof(new_p) = 'array' THEN
        IF jsonb_array_length(old_p) <> jsonb_array_length(new_p) THEN
            RETURN FALSE;
        END IF;
        FOR i IN 0 .. jsonb_array_length(old_p) - 1 LOOP
            IF NOT tsi_payload_change_ok(old_p -> i, new_p -> i) THEN
                RETURN FALSE;
            END IF;
        END LOOP;
        RETURN TRUE;
    END IF;
    RETURN old_p IS NOT DISTINCT FROM new_p;
END;
$$ LANGUAGE plpgsql STABLE;

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
    -- Inside the floor a payload may change only by erasure (a principal key
    -- re-keyed to its 'erased:' token) or by sealing a principal key in place.
    IF OLD.created_at > NOW() - INTERVAL '365 days'
       AND NEW.payload IS DISTINCT FROM OLD.payload
       AND NOT tsi_payload_change_ok(OLD.payload, NEW.payload) THEN
        RAISE EXCEPTION 'Rule 6(1)(e): webhook_deliveries.payload may not be altered before the one-year floor except by erasure';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---- P16-04: lookup HMACs under PII_LOOKUP_KEY --------------------------------

-- db/34's notification_deliveries floor with the lookup key, and one more
-- permitted change: the recipient HMAC re-keyed while the encrypted recipient
-- stays exactly as it was (scripts/rekey_pii_lookup.py).
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
        IF new_plain IS NULL
           OR NEW.recipient_hmac IS DISTINCT FROM encode(hmac(trim(new_plain), tsi_lookup_key(), 'sha256'), 'hex')
           OR (NEW.recipient_enc IS DISTINCT FROM OLD.recipient_enc AND new_plain NOT LIKE 'erased:%') THEN
            RAISE EXCEPTION 'Rule 6(1)(e): notification_deliveries.recipient may not be altered before the one-year floor except by erasure';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMIT;
