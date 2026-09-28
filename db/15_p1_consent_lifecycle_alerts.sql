-- 15_p1_consent_lifecycle_alerts.sql
-- P1 build-out from the MeitY/NeGD BRD API traceability workbook:
--   * Purpose lifecycle (PL-01..04) — the substitute for consent renewal
--   * Fiduciary / processor alerts (NT-06..08) — the BRD-named /api/alerts/notify
--   * Re-consent requests on material policy change (CU-02, CU-03)
--   * Notification delivery tracking (NT-04) for the delivery adapter
--   * Webhook dispatch tracking (CC-09, CU-08, CW-08) for the webhook dispatcher
--
-- Idempotent: safe to apply to an existing deployment.

-- ============================================================
-- Purpose lifecycle — one row per (fiduciary, purpose).
-- 'Open-ended' and 'time-bound' are recorded here (PL-01) so the choice the
-- principal reads in the notice is also the state the system enforces.
-- ============================================================
CREATE TABLE IF NOT EXISTS purpose_lifecycle (
    fiduciary_id         UUID NOT NULL REFERENCES fiduciaries(id),
    purpose_id           VARCHAR(255) NOT NULL,             -- id declared in the policy JSON
    duration_type        VARCHAR(20) NOT NULL DEFAULT 'OPEN_ENDED', -- OPEN_ENDED | TIME_BOUND
    state                VARCHAR(20) NOT NULL DEFAULT 'OPEN',       -- OPEN | CLOSED
    consent_expiry_days  INTEGER,                                    -- used only when duration_type = TIME_BOUND
    opened_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),         -- clock start for time-bound purposes
    closed_at            TIMESTAMPTZ,
    closed_by            UUID REFERENCES operators(id),
    closure_reason       TEXT,
    deidentification_action VARCHAR(50),                             -- ERASE | DE_IDENTIFY
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (fiduciary_id, purpose_id)
);

CREATE INDEX IF NOT EXISTS idx_purpose_lifecycle_state
    ON purpose_lifecycle (duration_type, state, opened_at);

-- ============================================================
-- Alerts — the BRD's /api/alerts/notify. Consent-change events delivered to
-- fiduciaries / processors, who confirm they acted (NT-06, NT-08).
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id      UUID NOT NULL REFERENCES fiduciaries(id),
    recipient_type    VARCHAR(20) NOT NULL,                   -- FIDUCIARY | PROCESSOR | PRINCIPAL
    recipient_id      VARCHAR(255),                           -- processor/app id or principal id
    alert_type        VARCHAR(100) NOT NULL,                  -- e.g. CONSENT_WITHDRAWN, PURPOSE_CLOSED
    event_ref_id      VARCHAR(255),                           -- consent record / purge request id
    payload           JSONB NOT NULL DEFAULT '{}',
    status            VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- PENDING | ACKNOWLEDGED | ESCALATED
    requires_action   BOOLEAN NOT NULL DEFAULT TRUE,
    acknowledged_at   TIMESTAMPTZ,
    acknowledged_by   VARCHAR(255),
    attempt_count     INTEGER NOT NULL DEFAULT 0,
    last_dispatched_at TIMESTAMPTZ,
    escalated_at      TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_pending
    ON alerts (status, created_at) WHERE status = 'PENDING';
CREATE INDEX IF NOT EXISTS idx_alerts_recipient
    ON alerts (fiduciary_id, recipient_id, created_at DESC);

-- ============================================================
-- Re-consent requests — a material policy change requires fresh affirmative
-- consent from every principal with active consent on the previous version
-- (CU-02, CU-03).
-- ============================================================
CREATE TABLE IF NOT EXISTS reconsent_requests (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id      UUID NOT NULL REFERENCES fiduciaries(id),
    policy_id         VARCHAR(255) NOT NULL,
    policy_version    VARCHAR(10) NOT NULL,
    user_id           VARCHAR(255) NOT NULL,
    reason            VARCHAR(500),
    status            VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- PENDING | GRANTED | WITHDRAWN | CLOSED
    requested_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    responded_at      TIMESTAMPTZ,
    consent_record_id UUID REFERENCES consent_records(id),
    UNIQUE (fiduciary_id, policy_id, policy_version, user_id)
);

-- ============================================================
-- Notification delivery — one row per (notification, channel) so the delivery
-- adapter (email / SMS / push / in-app) can retry independently and the audit
-- can show exactly what was attempted (NT-04).
-- ============================================================
CREATE TABLE IF NOT EXISTS notification_deliveries (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    notification_id   UUID NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    channel           VARCHAR(20) NOT NULL,                   -- EMAIL | SMS | PUSH | IN_APP
    recipient         VARCHAR(255),                           -- resolved address / device id
    status            VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- PENDING | SENT | FAILED | SKIPPED
    attempt_count     INTEGER NOT NULL DEFAULT 0,
    last_attempt_at   TIMESTAMPTZ,
    last_error        TEXT,
    sent_at           TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notification_deliveries_pending
    ON notification_deliveries (status, created_at);

-- ============================================================
-- Webhook dispatch — one row per queued event. HMAC-signed delivery is retried
-- by the dispatcher worker; response codes are kept for the audit (CC-09,
-- CU-08, CW-08).
-- ============================================================
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fiduciary_id        UUID NOT NULL REFERENCES fiduciaries(id),
    category            VARCHAR(20) NOT NULL,                 -- NOTIFICATION | PURGE | OTP
    event_type          VARCHAR(100) NOT NULL,
    payload             JSONB NOT NULL DEFAULT '{}',
    status              VARCHAR(20) NOT NULL DEFAULT 'PENDING', -- PENDING | DISPATCHED | FAILED
    attempt_count       INTEGER NOT NULL DEFAULT 0,
    last_dispatched_at  TIMESTAMPTZ,
    last_error          TEXT,
    response_status_code INTEGER,
    dispatched_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_pending
    ON webhook_deliveries (status, created_at);