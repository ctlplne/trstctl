-- Owner decision 2026-10-24 (A120/A130/A132): a per-tenant switch over control-plane key generation.
--
-- The control plane can generate a subject private key for a requester on three deprecated paths: identity
-- issuance without a CSR (and its renewals), PKI-secret issuance by common name (including the Vault-compatible
-- pki/issue route), and the compatibility Workload API socket. Each tenant's decision is projected from its own
-- tenant.control_plane_keygen.set events and confined by RLS. A tenant without a row has not been decided yet and
-- keeps the behavior it had before the switch existed.
CREATE TABLE IF NOT EXISTS tenant_control_plane_keygen (
    tenant_id uuid        PRIMARY KEY,
    enabled   boolean     NOT NULL,
    source    text        NOT NULL CHECK (source IN ('registration', 'upgrade', 'operator')),
    reason    text        NOT NULL DEFAULT '',
    set_by    text        NOT NULL DEFAULT '',
    set_at    timestamptz NOT NULL,
    evidence  jsonb
);
ALTER TABLE tenant_control_plane_keygen ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_control_plane_keygen FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_control_plane_keygen_isolation ON tenant_control_plane_keygen;
CREATE POLICY tenant_control_plane_keygen_isolation ON tenant_control_plane_keygen
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_control_plane_keygen TO trstctl_app;
