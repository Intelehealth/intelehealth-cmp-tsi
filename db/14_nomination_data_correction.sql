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

-- db/34 replaces nominations.nominating_principal_id with nominating_principal_id_hmac and rebuilds this index under
-- the same name; skip once the plaintext column is gone so this file stays re-runnable.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'nominations' AND column_name = 'nominating_principal_id') THEN
        CREATE INDEX IF NOT EXISTS idx_nominations_fiduciary_nominator
            ON nominations (fiduciary_id, nominating_principal_id);
    END IF;
END $$;

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

-- db/34 replaces data_correction_requests.user_id with user_id_hmac and rebuilds this index under
-- the same name; skip once the plaintext column is gone so this file stays re-runnable.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'data_correction_requests' AND column_name = 'user_id') THEN
        CREATE INDEX IF NOT EXISTS idx_data_correction_fiduciary_user
            ON data_correction_requests (fiduciary_id, user_id, created_at DESC);
    END IF;
END $$;
