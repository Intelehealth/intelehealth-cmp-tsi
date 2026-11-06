-- ============================================================================
-- db/27_p11_remediation.sql
--
-- Workbook v9 remediation. Idempotent; safe to re-run.
--
--   P11-01 the consent_records maintenance guard tests "granted" exactly as
--          consent.py's _point_granted does (Python truthiness of
--          consent_granted, else the legacy status alias), so no spelling the
--          application honours - status 'true', consent_granted 'True', 1 -
--          can turn a refused purpose into a granted one.
--   P11-02 the same guard rejects a data_point_consents value that is not an
--          array instead of coercing it, so one UPDATE can no longer replace
--          every recorded decision.
--   P11-09 the two legacy template names db/26 kept (PURGE_ONHOLD_NOTIFICATION,
--          EXPIRY_NOTIFICATION) are archived with the live type each maps to,
--          and removed; their text is not merged into the live type (P12-07).
-- ============================================================================

-- ---- P11-01: one definition of "granted", shared with the application ----------
-- Mirrors services/consent.py _point_granted:
--   consent_granted present and not JSON null -> Python truthiness of the value
--     (false, 0, "", [] and {} are refused; everything else is granted);
--   otherwise lower(str(status)) IN ('granted', 'true', 'consent_given').
-- With check_expiry, a consent_expiry in the past makes the grant lapse, as it
-- does in the application. An unparseable expiry is ignored, as there.
CREATE OR REPLACE FUNCTION tsi_point_granted(point JSONB, check_expiry BOOLEAN DEFAULT TRUE)
RETURNS BOOLEAN AS $$
DECLARE
    v JSONB;
    granted BOOLEAN;
    expiry TIMESTAMPTZ;
BEGIN
    IF point IS NULL OR jsonb_typeof(point) <> 'object' THEN
        RETURN FALSE;
    END IF;
    v := point -> 'consent_granted';
    IF v IS NULL OR jsonb_typeof(v) = 'null' THEN
        granted := lower(COALESCE(point ->> 'status', '')) IN ('granted', 'true', 'consent_given');
    ELSE
        granted := CASE jsonb_typeof(v)
            WHEN 'boolean' THEN v = 'true'::jsonb
            WHEN 'number'  THEN (v #>> '{}')::numeric <> 0
            WHEN 'string'  THEN (v #>> '{}') <> ''
            WHEN 'array'   THEN jsonb_array_length(v) > 0
            WHEN 'object'  THEN v <> '{}'::jsonb
            ELSE FALSE
        END;
    END IF;
    IF NOT granted THEN
        RETURN FALSE;
    END IF;
    IF check_expiry AND COALESCE(point ->> 'consent_expiry', '') <> '' THEN
        BEGIN
            expiry := (point ->> 'consent_expiry')::timestamptz;
            IF expiry <= NOW() THEN
                RETURN FALSE;
            END IF;
        EXCEPTION WHEN others THEN
            NULL;  -- unparseable: ignored, as _point_granted ignores it
        END;
    END IF;
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql STABLE;

-- services/base.py point_purpose_id: the first non-empty alias, canonical.
CREATE OR REPLACE FUNCTION tsi_point_purpose(point JSONB) RETURNS TEXT AS $$
    SELECT CASE WHEN point IS NULL OR jsonb_typeof(point) <> 'object' THEN ''
                ELSE COALESCE(tsi_canonical_purpose(COALESCE(
                         NULLIF(point ->> 'data_point_id', ''),
                         NULLIF(point ->> 'purpose_id', ''),
                         NULLIF(point ->> 'id', ''))), '') END;
$$ LANGUAGE sql IMMUTABLE;

CREATE OR REPLACE FUNCTION consent_records_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND COALESCE(current_setting('tsi.consent_maintenance', true), '') = 'on'
       AND NOT (OLD.is_active_consent IS FALSE AND NEW.is_active_consent IS TRUE)
       AND (to_jsonb(NEW) - 'user_id' - 'ip_address' - 'user_agent' - 'data_point_consents'
                          - 'last_updated_at' - 'is_active_consent')
         = (to_jsonb(OLD) - 'user_id' - 'ip_address' - 'user_agent' - 'data_point_consents'
                          - 'last_updated_at' - 'is_active_consent')
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

-- ---- P11-09: legacy template names -> live types ---------------------------------
-- EXPIRY_NOTIFICATION   -> PURPOSE_CLOSED  (DD-01: purpose closure replaced expiry)
-- PURGE_ONHOLD_NOTIFICATION -> ERASURE_REQUESTED_NOTIFICATION (the principal's
--   erasure acknowledgement, which is what reports a request held under law)
-- Every legacy row is archived verbatim, with the live type it maps to, and
-- then removed. P12-07: the legacy text is NOT merged into the live type - it
-- was written for a different event (an 'on hold' notice is not an erasure
-- acknowledgement), so a language the live template lacks falls back to the
-- default text instead. The DPO re-homes archived text by hand; the console
-- shows it beside the live type.
CREATE TABLE IF NOT EXISTS notification_message_templates_archive (
    fiduciary_id      UUID NOT NULL,
    notification_type VARCHAR(100) NOT NULL,
    messages          JSONB NOT NULL,
    migrated_to       VARCHAR(100),
    archived_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (fiduciary_id, notification_type)
);

INSERT INTO notification_message_templates_archive (fiduciary_id, notification_type, messages, migrated_to)
SELECT t.fiduciary_id, t.notification_type, t.messages,
       CASE t.notification_type WHEN 'EXPIRY_NOTIFICATION' THEN 'PURPOSE_CLOSED'
                                ELSE 'ERASURE_REQUESTED_NOTIFICATION' END
FROM notification_message_templates t
WHERE t.notification_type IN ('PURGE_ONHOLD_NOTIFICATION', 'EXPIRY_NOTIFICATION')
ON CONFLICT (fiduciary_id, notification_type) DO UPDATE SET
    messages = EXCLUDED.messages, migrated_to = EXCLUDED.migrated_to, archived_at = NOW();

DELETE FROM notification_message_templates
WHERE notification_type IN ('PURGE_ONHOLD_NOTIFICATION', 'EXPIRY_NOTIFICATION');
