-- PAM target registrations are immutable tenant-owned configuration. Operators
-- disable a target rather than rewriting a destination that custodians approved.
CREATE TABLE pam_targets (
    tenant_id uuid NOT NULL,
    target_type text NOT NULL CHECK (target_type IN ('postgres', 'ssh')),
    id text NOT NULL,
    provider_id text NOT NULL DEFAULT '',
    allowed_roles text[] NOT NULL DEFAULT '{}',
    host text NOT NULL DEFAULT '',
    port integer NOT NULL DEFAULT 0,
    principals text[] NOT NULL DEFAULT '{}',
    enabled boolean NOT NULL DEFAULT true,
    registered_by text NOT NULL,
    registered_at timestamptz NOT NULL,
    disabled_by text NOT NULL DEFAULT '',
    disabled_reason text NOT NULL DEFAULT '',
    disabled_at timestamptz,
    PRIMARY KEY (tenant_id, target_type, id)
);

ALTER TABLE pam_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_targets_isolation ON pam_targets
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_targets TO trstctl_app;
