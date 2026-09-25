-- Completion is proved by a committed projection transaction, never inferred
-- from current rows or timestamps. Ordered rebuild populates legacy history.
CREATE TABLE provider_authority_projection_receipts (
    tenant_id uuid NOT NULL,
    event_sequence bigint NOT NULL CHECK (event_sequence > 0),
    event_id text NOT NULL CHECK (event_id <> ''),
    event_digest text NOT NULL CHECK (event_digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (tenant_id, event_sequence),
    UNIQUE (tenant_id, event_id)
);
ALTER TABLE provider_authority_projection_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_authority_projection_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY provider_authority_projection_receipts_isolation ON provider_authority_projection_receipts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON provider_authority_projection_receipts TO trstctl_app;

-- A populated pre-receipt installation has unknown completion, even when its
-- current rows look correct. Bootstrap must recover retained authority first.
CREATE TABLE provider_authority_projection_state (
    tenant_id uuid PRIMARY KEY,
    needs_rebuild boolean NOT NULL
);
ALTER TABLE provider_authority_projection_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_authority_projection_state FORCE ROW LEVEL SECURITY;
CREATE POLICY provider_authority_projection_state_isolation ON provider_authority_projection_state
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON provider_authority_projection_state TO trstctl_app;
INSERT INTO provider_authority_projection_state (tenant_id, needs_rebuild)
VALUES ('00000000-0000-0000-0000-000000000000',
    EXISTS (SELECT 1 FROM provider_tenants) OR
    EXISTS (SELECT 1 FROM provider_operators) OR
    EXISTS (SELECT 1 FROM provider_operator_delegations) OR
    EXISTS (SELECT 1 FROM provider_breakglass_grants) OR
    EXISTS (SELECT 1 FROM provider_tenant_quotas) OR
    EXISTS (SELECT 1 FROM tenant_branding));
