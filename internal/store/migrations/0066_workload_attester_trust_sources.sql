-- Tenant-managed workload attester trust sources (JOURNEY-001 / F30).
-- Changes are projected from workload.attester_trust_source.* events. The table
-- stores public trust material and policy metadata only: JWKS documents, public
-- root certificates, issuer/audience, nonce policy, and lifecycle evidence.

CREATE TABLE workload_attester_trust_sources (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    method text NOT NULL,
    issuer text NOT NULL DEFAULT '',
    audience text NOT NULL DEFAULT '',
    jwks jsonb NOT NULL DEFAULT '{}'::jsonb,
    root_certs_pem text[] NOT NULL DEFAULT '{}'::text[],
    expected_nonce_base64 text NOT NULL DEFAULT '',
    enabled boolean NOT NULL DEFAULT true,
    revoked_at timestamptz,
    revoked_reason text NOT NULL DEFAULT '',
    rotation_version integer NOT NULL DEFAULT 1,
    last_rotated_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id)
);

CREATE UNIQUE INDEX workload_attester_trust_sources_tenant_name_idx
    ON workload_attester_trust_sources (tenant_id, lower(name));

CREATE INDEX workload_attester_trust_sources_method_idx
    ON workload_attester_trust_sources (tenant_id, method, enabled, id);

ALTER TABLE workload_attester_trust_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE workload_attester_trust_sources FORCE  ROW LEVEL SECURITY;

CREATE POLICY workload_attester_trust_sources_isolation ON workload_attester_trust_sources
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON workload_attester_trust_sources TO trstctl_app;
