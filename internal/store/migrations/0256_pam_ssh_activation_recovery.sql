-- A signer can finish after approval is consumed but before pam.session.started
-- reaches the event log. Keep the SSH intent as a tenant-scoped projection so
-- a restarted worker can revoke its deterministic key ID before another use.
CREATE TABLE pam_ssh_activations (
    tenant_id uuid NOT NULL,
    session_id uuid NOT NULL,
    request_id uuid NOT NULL,
    key_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'revoking', 'completed', 'recovered')),
    requested_at timestamptz NOT NULL,
    completed_at timestamptz,
    revocation_requested_at timestamptz,
    recovered_at timestamptz,
    PRIMARY KEY (tenant_id, session_id)
);

CREATE INDEX pam_ssh_activations_pending_idx
    ON pam_ssh_activations (requested_at, tenant_id, session_id)
    WHERE status = 'pending';

ALTER TABLE pam_ssh_activations ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_ssh_activations FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_ssh_activations_isolation ON pam_ssh_activations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_ssh_activations TO trstctl_app;
