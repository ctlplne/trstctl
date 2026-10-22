-- A70: a per-ring soak window for staged agent upgrades.
--
-- A ring that verified advanced at once. A build that comes up, answers the
-- control plane and then degrades minutes later reached the next ring before
-- anyone saw it. soak_seconds makes a verified ring stay verified for that
-- long before the next ring is dispatched; zero keeps the immediate advance.
-- Existing campaigns keep zero: nothing they were opened with is reinterpreted.
ALTER TABLE agent_upgrade_campaigns
    ADD COLUMN IF NOT EXISTS soak_seconds integer NOT NULL DEFAULT 0;
COMMENT ON COLUMN agent_upgrade_campaigns.soak_seconds IS
    'A70: seconds a verified ring must stay healthy before the next ring dispatches; 0 advances at once.';
