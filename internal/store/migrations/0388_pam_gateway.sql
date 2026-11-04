-- A254: the credential-hidden access gateway. A PAM target may name the
-- gateway-role agent that serves it and the address clients reach it at; a
-- session to such a target is delivered through that gateway as one agent job:
-- the requester receives a one-time ticket (stored here only as its SHA-256),
-- never the upstream credential, which only the gateway redeems.
ALTER TABLE pam_targets
    ADD COLUMN IF NOT EXISTS gateway_agent_id uuid,
    ADD COLUMN IF NOT EXISTS gateway_address text NOT NULL DEFAULT '';

ALTER TABLE pam_sessions
    ADD COLUMN IF NOT EXISTS delivery text NOT NULL DEFAULT 'direct'
        CHECK (delivery IN ('direct', 'gateway')),
    ADD COLUMN IF NOT EXISTS gateway_agent_id uuid,
    ADD COLUMN IF NOT EXISTS gateway_ticket_digest text NOT NULL DEFAULT '';

-- A gateway session is an outbox row only a gateway-role agent may claim.
ALTER TABLE outbox DROP CONSTRAINT IF EXISTS outbox_required_agent_role_known;
ALTER TABLE outbox
    ADD CONSTRAINT outbox_required_agent_role_known
    CHECK (required_agent_role IN ('', 'host', 'network', 'control_plane', 'gateway'));

-- The gateway role joins the closed set of grantable agent roles. An agent
-- holding it serves brokered access sessions and holds their upstream
-- credentials; granting it is a deliberate act (agents:relay.grant), like the
-- network relay. Existing tokens keep their grants.
ALTER TABLE agent_bootstrap_tokens DROP CONSTRAINT IF EXISTS agent_bootstrap_tokens_roles_known;
ALTER TABLE agent_bootstrap_tokens
    ADD CONSTRAINT agent_bootstrap_tokens_roles_known
    CHECK (granted_roles <@ ARRAY['host', 'network', 'observer', 'gateway']::text[]);
