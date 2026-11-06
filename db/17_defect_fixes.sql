-- 17_defect_fixes.sql
-- Schema support for the fixes to the "Open Defects" sheet of
-- MeitY_BRD_API_Traceability_v3.xlsx:
--   #1  principal_otps          — server-side, expiring, single-use principal login codes
--   #6  roles.fiduciary_id      — custom roles scoped per tenant; built-in roles
--                                 extended to cover every admin service now gated
--   #8  operators.mfa_*         — TOTP replay protection and lockout
--   #9  purge_requests CHECK    — status restricted to the known enum
--
-- Idempotent: safe to apply to an existing deployment.

-- ============================================================
-- #1 Principal login OTPs. Only an HMAC of the code is stored, bound to an
-- HMAC of (fiduciary, principal) so a database read reveals neither.
-- ============================================================
CREATE TABLE IF NOT EXISTS principal_otps (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id  UUID NOT NULL REFERENCES fiduciaries(id),
    subject_hash  VARCHAR(64) NOT NULL,
    code_hash     VARCHAR(64) NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 0,
    expires_at    TIMESTAMPTZ NOT NULL,
    consumed_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_principal_otps_subject
    ON principal_otps (subject_hash, created_at DESC);

-- ============================================================
-- #8 TOTP replay protection: the last accepted time-step counter, plus a
-- failed-attempt counter and lockout for verify_mfa.
-- ============================================================
ALTER TABLE operators
    ADD COLUMN IF NOT EXISTS mfa_last_counter     BIGINT,
    ADD COLUMN IF NOT EXISTS mfa_failed_attempts  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS mfa_locked_until     TIMESTAMPTZ;

-- ============================================================
-- #6 Roles per tenant. fiduciary_id NULL = a global role (the built-ins);
-- a tenant's custom role carries its fiduciary_id. A role code is unique
-- within its scope rather than globally, so the primary key moves to id.
-- ============================================================
ALTER TABLE roles ADD COLUMN IF NOT EXISTS id UUID NOT NULL DEFAULT uuid_generate_v4();
ALTER TABLE roles ADD COLUMN IF NOT EXISTS fiduciary_id UUID REFERENCES fiduciaries(id);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
        WHERE c.conrelid = 'roles'::regclass AND c.contype = 'p' AND a.attname = 'code'
    ) THEN
        ALTER TABLE roles DROP CONSTRAINT roles_pkey;
        ALTER TABLE roles ADD CONSTRAINT roles_pkey PRIMARY KEY (id);
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_scope_code
    ON roles ((COALESCE(fiduciary_id, '00000000-0000-0000-0000-000000000000'::uuid)), code);

-- Every admin service is now permission-gated (<resource>:read|write|manage).
-- Extend the global built-ins so each keeps the console surface it already
-- used. Additive only: permissions an administrator already set are kept.
UPDATE roles SET permissions = (
    SELECT jsonb_agg(DISTINCT p ORDER BY p)
    FROM jsonb_array_elements_text(roles.permissions || '["fiduciary:read","app:read","operator:write","breach:write","ropa:write","legal:write","job:write","dashboard:read","alert:write","purpose:write","rights:write"]'::jsonb) AS p
) WHERE code = 'DPO' AND fiduciary_id IS NULL;

UPDATE roles SET permissions = (
    SELECT jsonb_agg(DISTINCT p ORDER BY p)
    FROM jsonb_array_elements_text(roles.permissions || '["fiduciary:read","app:read","operator:read","purge:write","grievance:write","breach:read","ropa:read","dashboard:read","alert:read","rights:read"]'::jsonb) AS p
) WHERE code = 'OPERATOR' AND fiduciary_id IS NULL;

UPDATE roles SET permissions = (
    SELECT jsonb_agg(DISTINCT p ORDER BY p)
    FROM jsonb_array_elements_text(roles.permissions || '["fiduciary:read","app:read","purge:read","breach:read","ropa:read","legal:read","job:read","retention:read","dashboard:read","alert:read","purpose:read","rights:read"]'::jsonb) AS p
) WHERE code = 'AUDITOR' AND fiduciary_id IS NULL;

-- ============================================================
-- #9 Purge request status enum (mirrors compliance.PURGE_STATUSES). NOT VALID
-- so legacy rows with free-text statuses do not block the upgrade; every new
-- write is checked. Run VALIDATE CONSTRAINT once old rows are cleaned up.
-- ============================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_purge_requests_status') THEN
        ALTER TABLE purge_requests ADD CONSTRAINT chk_purge_requests_status CHECK (status IN (
            'PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'UNDER_LEGAL_HOLD',
            'PURGE_IN_PROGRESS', 'PURGE_COMPLETED', 'PURGE_FAILED', 'LEGAL_HOLD_APPLIED'
        )) NOT VALID;
    END IF;
END $$;
