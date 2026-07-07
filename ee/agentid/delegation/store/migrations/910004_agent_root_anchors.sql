-- AGID root-anchor registry (ee/agentid/delegation/store) - proprietary
-- Enterprise/Provider. This table is the tenant-owned root-of-trust registry
-- for signer-verified delegation chains. The signer itself never reads SQL
-- (AN-4); this table is the control-plane source that can be exported to the
-- signer's durable provisioning directory.

CREATE TABLE agent_root_anchors (
    tenant_id  uuid        NOT NULL,
    key_id     text        NOT NULL,
    public_der bytea       NOT NULL,
    auth_ref   text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key_id)
);

ALTER TABLE agent_root_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_root_anchors FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_root_anchors_isolation ON agent_root_anchors
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_root_anchors TO trstctl_app;
