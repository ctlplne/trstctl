-- A91: agent lifecycle receipts, an event-derived record of when each agent
-- was first seen and when it was offboarded, kept apart from the agents read
-- model so the agents usage gauge can be recounted from a record the gauge
-- itself never writes. Existing agents are captured once from their projected
-- row (created_at as first_seen_at, offboarded_at as is) so a tenant that
-- predates this release reconciles from the same baseline; from here on the
-- heartbeat, renewal and offboarding projections write the receipts.
CREATE TABLE IF NOT EXISTS agent_lifecycle_receipts (
    tenant_id     uuid        NOT NULL,
    agent_id      uuid        NOT NULL,
    first_seen_at timestamptz NOT NULL,
    offboarded_at timestamptz,
    PRIMARY KEY (tenant_id, agent_id)
);

ALTER TABLE agent_lifecycle_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_lifecycle_receipts FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS agent_lifecycle_receipts_isolation ON agent_lifecycle_receipts;
CREATE POLICY agent_lifecycle_receipts_isolation ON agent_lifecycle_receipts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_lifecycle_receipts TO trstctl_app;

INSERT INTO agent_lifecycle_receipts (tenant_id, agent_id, first_seen_at, offboarded_at)
SELECT tenant_id, id, created_at, offboarded_at FROM agents
ON CONFLICT (tenant_id, agent_id) DO NOTHING;
