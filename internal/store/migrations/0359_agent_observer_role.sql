-- X1: the observer role joins the closed set of grantable agent roles. An agent
-- holding it watches an interface's connection handshakes; granting it is a
-- deliberate act (agents:relay.grant), like the network relay. Existing tokens
-- keep their grants.
ALTER TABLE agent_bootstrap_tokens DROP CONSTRAINT IF EXISTS agent_bootstrap_tokens_roles_known;
ALTER TABLE agent_bootstrap_tokens
    ADD CONSTRAINT agent_bootstrap_tokens_roles_known
    CHECK (granted_roles <@ ARRAY['host', 'network', 'observer']::text[]);
