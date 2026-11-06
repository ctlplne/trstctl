-- A264: immutable reviewed cloud change intents and native readback results.
CREATE TABLE cloud_machine_changes (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    intent jsonb NOT NULL,
    state text NOT NULL CHECK (state IN ('awaiting_approval', 'queued', 'verified', 'failed')),
    approval_request_id uuid NOT NULL,
    intent_digest text NOT NULL,
    requested_by text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    result jsonb,
    event_sequence bigint NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX cloud_machine_changes_tenant_state ON cloud_machine_changes (tenant_id, state, id);
ALTER TABLE cloud_machine_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_machine_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY cloud_machine_changes_isolation ON cloud_machine_changes
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON cloud_machine_changes TO trstctl_app;
