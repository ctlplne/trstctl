-- A served agent name belongs to the certificate enrolled for it. These rows
-- are a projection of agent.cert.enrolled and agent.cert.renewed schema 3.
CREATE TABLE agent_certificate_bindings (
    tenant_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    serial text NOT NULL,
    fingerprint text NOT NULL,
    not_after timestamptz NOT NULL,
    event_seq bigint NOT NULL,
    PRIMARY KEY (tenant_id, agent_id, serial)
);
ALTER TABLE agent_certificate_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_certificate_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_certificate_bindings_isolation ON agent_certificate_bindings
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_certificate_bindings TO trstctl_app;
