-- How a grievance reached the fiduciary. Portal/API submissions are always
-- PORTAL; a DPO logging one that arrived offline records the real channel.
ALTER TABLE grievances ADD COLUMN IF NOT EXISTS channel VARCHAR(20) NOT NULL DEFAULT 'PORTAL';

ALTER TABLE grievances DROP CONSTRAINT IF EXISTS grievances_channel_check;
ALTER TABLE grievances ADD CONSTRAINT grievances_channel_check
    CHECK (channel IN ('PORTAL', 'EMAIL', 'PHONE', 'LETTER', 'IN_PERSON', 'OTHER'));

COMMENT ON COLUMN grievances.channel IS
    'How the grievance was received: PORTAL (self-service / API) or an offline channel logged by a DPO.';
