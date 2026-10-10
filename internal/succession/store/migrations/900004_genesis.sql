-- Public, signer-attested first-use anchor for a tenant-scoped PCAS identity.
-- The append-only event is truth; this RLS table serves the verified anchor.
CREATE TABLE pcas_genesis (
    tenant_id uuid NOT NULL,
    identity_id text NOT NULL,
    genesis_json jsonb NOT NULL,
    trust_root_public_der bytea NOT NULL,
    event_id text NOT NULL,
    request_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, identity_id),
    UNIQUE (tenant_id, request_id)
);

ALTER TABLE pcas_genesis ENABLE ROW LEVEL SECURITY;
ALTER TABLE pcas_genesis FORCE ROW LEVEL SECURITY;
CREATE POLICY pcas_genesis_isolation ON pcas_genesis
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT ON pcas_genesis TO trstctl_app;
