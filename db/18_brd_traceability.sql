-- 18_brd_traceability.sql
-- Schema for closing the open rows of the "BRD Traceability" sheet in
-- MeitY_BRD_API_Traceability_v3.xlsx (requirement IDs in each section).
--
-- Idempotent: safe to apply to an existing deployment.

-- ============================================================
-- CC-04 / CC-06 / CC-07 / CW-07 — consent records are append-only and carry
-- server-observed capture metadata. session_id comes from the CMS's own
-- principal session (session_source = 'CMS') or is an integrator's claim
-- ('CLIENT'); whatever the caller asserted is kept apart in client_metadata.
-- A withdrawal is a new record pointing at the one it supersedes.
-- ============================================================
ALTER TABLE consent_records
    ADD COLUMN IF NOT EXISTS session_id            VARCHAR(255),
    ADD COLUMN IF NOT EXISTS session_source        VARCHAR(10),
    ADD COLUMN IF NOT EXISTS client_metadata       JSONB,
    ADD COLUMN IF NOT EXISTS supersedes_record_id  UUID REFERENCES consent_records(id);

CREATE INDEX IF NOT EXISTS idx_consent_records_supersedes ON consent_records (supersedes_record_id);

-- ============================================================
-- CC-05 — guardian verification has an outcome. Rows written before this
-- script were never checked, so they are marked LEGACY_UNVERIFIED and cannot
-- back a minor's consent; new rows record VERIFIED / REJECTED / PENDING / ASSERTED.
-- ============================================================
ALTER TABLE parental_verification_logs
    ADD COLUMN IF NOT EXISTS verification_status VARCHAR(30) NOT NULL DEFAULT 'LEGACY_UNVERIFIED';
ALTER TABLE parental_verification_logs ALTER COLUMN verification_status SET DEFAULT 'ASSERTED';

-- ============================================================
-- PL-03 / CW-11 / SA-09 / SA-13 — purge requests say WHAT to do (erase or
-- de-identify), carry the legal basis when held, and record the processor's
-- completion evidence so completion is verified rather than assumed.
-- ============================================================
ALTER TABLE purge_requests
    ADD COLUMN IF NOT EXISTS action               VARCHAR(20) NOT NULL DEFAULT 'ERASE',
    ADD COLUMN IF NOT EXISTS legal_reference      TEXT,
    ADD COLUMN IF NOT EXISTS hold_until           TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS completion_evidence  JSONB,
    ADD COLUMN IF NOT EXISTS completed_at         TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS cms_erased_at        TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS overdue_notified_at  TIMESTAMPTZ;

-- ============================================================
-- GR-04 / GR-12 / GR-13 — grievance attachments, feedback on the resolution.
-- ============================================================
ALTER TABLE grievances
    ADD COLUMN IF NOT EXISTS feedback_rating    SMALLINT CHECK (feedback_rating BETWEEN 1 AND 5),
    ADD COLUMN IF NOT EXISTS feedback_comment   TEXT,
    ADD COLUMN IF NOT EXISTS feedback_at        TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS escalated_at       TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS grievance_attachments (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    grievance_id  UUID NOT NULL REFERENCES grievances(id),
    fiduciary_id  UUID NOT NULL REFERENCES fiduciaries(id),
    file_name     VARCHAR(255) NOT NULL,
    content_type  VARCHAR(100) NOT NULL,
    size_bytes    INTEGER NOT NULL,
    sha256        VARCHAR(64) NOT NULL,
    storage_path  TEXT NOT NULL,
    uploaded_by   VARCHAR(255) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_grievance_attachments_grievance ON grievance_attachments (grievance_id);

-- ============================================================
-- SA-05 — real-time access revocation. Deactivating an operator moves
-- tokens_valid_after forward; logout revokes the one token.
-- ============================================================
ALTER TABLE operators ADD COLUMN IF NOT EXISTS tokens_valid_after TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti         VARCHAR(64) PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expiry ON revoked_tokens (expires_at);
