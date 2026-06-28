-- Agent mTLS certificate revocations (WIRE-001 / RED-004).
--
-- This is a pure read-model projection of agent.cert.revoked events: the event log
-- is the source of truth, and this tenant-scoped table is the fast deny-list the
-- served agent gRPC channel consults before doing RPC work. A revocation is keyed
-- by tenant + stable agent id + either the presented certificate serial or its
-- SHA-256 DER fingerprint. The selector form lets operators revoke with whichever
-- public certificate identifier they have without storing certificate bytes here.
CREATE TABLE agent_cert_revocations (
    tenant_id     uuid        NOT NULL,
    agent_id      uuid        NOT NULL,
    agent_name    text        NOT NULL DEFAULT '',
    selector_type text        NOT NULL,
    selector      text        NOT NULL,
    reason        text        NOT NULL DEFAULT '',
    revoked_at    timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, agent_id, selector_type, selector),
    CONSTRAINT agent_cert_revocations_selector_type_chk
        CHECK (selector_type IN ('serial', 'fingerprint')),
    CONSTRAINT agent_cert_revocations_selector_chk
        CHECK (selector <> '')
);

ALTER TABLE agent_cert_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_cert_revocations FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_cert_revocations_isolation ON agent_cert_revocations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_cert_revocations TO trstctl_app;
