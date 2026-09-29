-- 16_p2_roles_mfa_retention.sql
-- P2 build-out from the MeitY/NeGD BRD API traceability workbook:
--   * Custom roles + permission hierarchy, incl. the Auditor role (SA-01/02/03)
--   * TOTP MFA for administrator accounts (SA-06) and audit-log gating (LG-06)
--   * Administrator-configurable retention policies (SA-08/10/12) — the primary
--     clock under DD-03
--
-- Idempotent: safe to apply to an existing deployment.

-- ============================================================
-- Roles — the BRD names ADMIN, DPO, AUDITOR and OPERATOR. Custom roles may be
-- added at runtime (SA-02). permissions is an array of capability strings;
-- "*" = full access.
-- ============================================================
CREATE TABLE IF NOT EXISTS roles (
    code          VARCHAR(32) PRIMARY KEY,
    name          VARCHAR(100) NOT NULL,
    description   TEXT,
    is_builtin    BOOLEAN NOT NULL DEFAULT FALSE,
    permissions   JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO roles (code, name, description, is_builtin, permissions) VALUES
    ('ADMIN',    'Administrator', 'Full access to every console capability.', TRUE,
        '["*"]'::jsonb),
    ('DPO',      'Data Protection Officer', 'Governance and data-subject workflows.', TRUE,
        '["consent:read","consent:write","policy:read","policy:write","purge:*","grievance:read","grievance:write","audit:read","notification:*","retention:*","role:read"]'::jsonb),
    ('AUDITOR',  'Auditor', 'Read-only access to audit logs, consents, policies and grievances for assurance work.', TRUE,
        '["consent:read","policy:read","grievance:read","audit:read"]'::jsonb),
    ('OPERATOR', 'Operator', 'Day-to-day operational tasks; no audit or role access.', TRUE,
        '["consent:read","consent:write","policy:read","purge:read","grievance:read","notification:read"]'::jsonb)
ON CONFLICT (code) DO NOTHING;

-- ============================================================
-- TOTP MFA for administrator accounts (SA-06). The shared secret is stored
-- encrypted at pgcrypto; only a verified session carries the mfa claim.
-- ============================================================
ALTER TABLE operators
    ADD COLUMN IF NOT EXISTS mfa_secret_enc    TEXT,
    ADD COLUMN IF NOT EXISTS mfa_enabled       BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS mfa_enrolled_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS mfa_verified_at   TIMESTAMPTZ;

-- ============================================================
-- Retention policies (SA-08) — the administrator-configurable schedule per
-- purpose / data category that replaces the hard-coded ROPA reading as the
-- primary clock under DD-03. legal_reference records the exemption rule relied
-- on when data is kept beyond the human default (SA-10).
-- ============================================================
CREATE TABLE IF NOT EXISTS retention_policies (
    id                         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id               UUID NOT NULL REFERENCES fiduciaries(id),
    name                       VARCHAR(255) NOT NULL,
    description                TEXT,
    applicable_purposes        JSONB NOT NULL DEFAULT '[]'::jsonb,
    applicable_data_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    retention_duration_value   INTEGER NOT NULL,
    retention_duration_unit    VARCHAR(10) NOT NULL DEFAULT 'DAYS',  -- DAYS | MONTHS | YEARS
    retention_start_event      VARCHAR(30) NOT NULL DEFAULT 'CESSATION',
    action_at_expiry           VARCHAR(20) NOT NULL DEFAULT 'ERASE', -- ERASE | DE_IDENTIFY
    legal_reference            TEXT,                                  -- SA-10 exemption rule
    status                     VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE | INACTIVE
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_retention_policies_fid
    ON retention_policies (fiduciary_id, status);

-- ============================================================
-- Grievance reference number + consent linkage (UD-10, GR-05, GR-14).
-- reference_number is a short human-quotable string a principal can raise in
-- follow-up contact; consent_record_id links the complaint to the consent
-- record it concerns.
-- ============================================================
ALTER TABLE grievances
    ADD COLUMN IF NOT EXISTS reference_number   VARCHAR(32),
    ADD COLUMN IF NOT EXISTS consent_record_id  UUID REFERENCES consent_records(id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_grievances_ref
    ON grievances (fiduciary_id, reference_number);

-- ============================================================
-- Audit metadata completion (LG-02, LG-03). Purpose ID, consent status,
-- initiator and source IP become discrete columns instead of being buried in
-- free-text context_details, so the four missing BRD fields are queryable.
-- ============================================================
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS purpose_id      VARCHAR(255),
    ADD COLUMN IF NOT EXISTS consent_status  VARCHAR(50),
    ADD COLUMN IF NOT EXISTS initiator       VARCHAR(255),
    ADD COLUMN IF NOT EXISTS source_ip       VARCHAR(100);