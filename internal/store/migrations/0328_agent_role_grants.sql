-- Operator-granted agent role changes.
--
-- An operator holding agents:relay.grant sets the roles an agent's next
-- certificate carries; the agent's next renewal signs them, with no
-- re-enrollment. Roles never come from the CSR: a renewal CSR asking for a
-- role the agent is not being given is refused.
--
-- A pure read-model projection: agent.roles.granted records the grant, and
-- the renewal that signs it (agent.cert.renewed, schema 2) names the grant's
-- event, so a newer grant recorded meanwhile is never marked applied by an
-- older renewal. One row per agent: a later grant replaces the earlier one,
-- ordered by event sequence so concurrent grants converge on the newest.
--
-- Who granted the roles and why stay in the event, where subject erasure
-- already reaches them; this row holds no names or free text.
CREATE TABLE IF NOT EXISTS agent_role_grants (
    tenant_id      uuid        NOT NULL,
    agent_id       uuid        NOT NULL,
    roles          text[]      NOT NULL,
    granted_at     timestamptz NOT NULL,
    event_id       text        NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    applied_serial text        NOT NULL DEFAULT '',
    applied_at     timestamptz,
    PRIMARY KEY (tenant_id, agent_id),
    CONSTRAINT agent_role_grants_roles_chk CHECK (cardinality(roles) > 0)
);

ALTER TABLE agent_role_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_role_grants FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS agent_role_grants_isolation ON agent_role_grants;
CREATE POLICY agent_role_grants_isolation ON agent_role_grants
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_role_grants TO trstctl_app;
