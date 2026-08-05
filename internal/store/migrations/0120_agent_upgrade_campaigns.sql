-- A5: staged agent-upgrade campaigns with a canary ring that can stop them.
--
-- Today an agent upgrade is a fleet-wide push. The failure that matters is not
-- "the upgrade job errored" — it is an agent that TOOK the new build, came back,
-- and cannot serve. A push finds that out on the whole fleet at once.

CREATE TABLE IF NOT EXISTS agent_upgrade_campaigns (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid NOT NULL,
    target_version text NOT NULL,
    -- pending | running | halted | paused | complete
    --
    -- halted and paused are separate columns' worth of meaning in one field:
    -- halted is the machine's finding that a build is bad, paused is a person
    -- stopping deliberately. An operator resuming a pause they made must not
    -- silently resume a halt they never saw.
    status        text NOT NULL DEFAULT 'pending',
    current_ring  text NOT NULL DEFAULT '',
    -- The ring that stopped it. Resume restarts HERE, not past it: skipping
    -- ahead would leave the agents whose failure halted the rollout on the
    -- broken build while the campaign reported success.
    halted_at_ring text NOT NULL DEFAULT '',
    reason        text NOT NULL DEFAULT '',
    created_by    text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- One active campaign per tenant. Two concurrent rollouts to the same fleet
-- would each see the other's agents as unexpectedly-versioned and halt each
-- other, or worse, not.
CREATE UNIQUE INDEX IF NOT EXISTS agent_upgrade_campaigns_active
    ON agent_upgrade_campaigns (tenant_id)
    WHERE status IN ('pending', 'running', 'halted', 'paused');

ALTER TABLE agent_upgrade_campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_upgrade_campaigns FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS agent_upgrade_campaigns_tenant_isolation ON agent_upgrade_campaigns;
CREATE POLICY agent_upgrade_campaigns_tenant_isolation ON agent_upgrade_campaigns
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_upgrade_campaigns TO trstctl_app;

-- Ring assignment lives on the agent, not in a campaign-scoped table: an
-- agent's ring is a property of the agent (is this box safe to break first?),
-- not of any one rollout. Empty means UNASSIGNED, which is deliberately not
-- 'broad' — an agent nobody placed should not silently join the largest ring.
