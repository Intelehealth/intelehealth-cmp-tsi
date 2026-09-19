-- DPDP Act, Section 8(6): a Data Fiduciary must notify the Data Protection Board
-- of India of a personal data breach within 72 hours of becoming aware of it.
-- Record the deadline on each breach incident so the workflow can be tracked and
-- a missed notification surfaced. Existing deployments get the column idempotently.
ALTER TABLE breach_incidents
    ADD COLUMN IF NOT EXISTS board_notification_deadline TIMESTAMPTZ;
