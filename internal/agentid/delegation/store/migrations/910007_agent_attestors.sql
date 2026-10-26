-- AGID tenant attestor registry (internal/agentid/delegation/store). Each row
-- binds a tenant's attestor key ID to the public key that signs its attestation
-- evidence and the attestation method that evidence is for. It is the RLS
-- serving copy of the immutable agent.attestor.registered events; the isolated
-- signer never reads SQL (AN-4) and holds its own copy of each binding, which
-- the control plane provisions over the signer transport and reads back.

CREATE TABLE agent_attestors (
    tenant_id  uuid        NOT NULL,
    key_id     text        NOT NULL,
    method     text        NOT NULL,
    public_der bytea       NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key_id)
);

ALTER TABLE agent_attestors ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_attestors FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_attestors_isolation ON agent_attestors
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_attestors TO trstctl_app;
