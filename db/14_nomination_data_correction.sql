-- DPDP Act, Section 15: a Data Principal may nominate another person to exercise
-- their rights on their behalf in the event of death or incapacity.
CREATE TABLE IF NOT EXISTS nominations (
    id                       UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id             UUID NOT NULL REFERENCES fiduciaries(id),
    nominating_principal_id  VARCHAR(255) NOT NULL,
    nominated_principal_id   VARCHAR(255) NOT NULL,
    relationship             VARCHAR(100),
    valid_from               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until              TIMESTAMPTZ,
    status                   VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, REVOKED, EXPIRED
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_nominations_fiduciary_nominator
    ON nominations (fiduciary_id, nominating_principal_id);

-- Data correction requests: the DPDP right for a Data Principal to request that
-- their personal data be corrected or completed.
CREATE TABLE IF NOT EXISTS data_correction_requests (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id     UUID NOT NULL REFERENCES fiduciaries(id),
    user_id          VARCHAR(255) NOT NULL,
    field_name       VARCHAR(255) NOT NULL,
    current_value    TEXT,
    requested_value  TEXT NOT NULL,
    reason           TEXT,
    status           VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- PENDING, IN_PROGRESS, APPROVED, REJECTED
    resolution_note  TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at      TIMESTAMPTZ,
    last_updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_data_correction_fiduciary_user
    ON data_correction_requests (fiduciary_id, user_id, created_at DESC);
