-- A Provider suspension denies customer service before its event is published.
-- This independent receiver survives read-model replay and PostgreSQL restore.
CREATE TABLE provider_suspend_commands (
    tenant_id uuid NOT NULL,
    event_id text NOT NULL,
    event_time timestamptz NOT NULL,
    event_actor jsonb,
    event_payload bytea,
    payload_sha256 char(64),
    status text NOT NULL DEFAULT 'pending',
    projected_sequence bigint,
    released_by_event_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, event_id),
    CHECK ((status = 'pending' AND event_payload IS NOT NULL AND
            payload_sha256 ~ '^[0-9a-f]{64}$' AND projected_sequence IS NULL AND
            released_by_event_id IS NULL) OR
           (status = 'completed' AND event_payload IS NULL AND payload_sha256 IS NULL AND
            event_actor IS NULL AND projected_sequence > 0 AND released_by_event_id IS NULL) OR
           (status = 'released' AND event_payload IS NULL AND payload_sha256 IS NULL AND
            event_actor IS NULL AND projected_sequence > 0 AND released_by_event_id IS NOT NULL))
);
CREATE UNIQUE INDEX provider_suspend_commands_active
    ON provider_suspend_commands (tenant_id)
    WHERE status IN ('pending', 'completed');
CREATE INDEX provider_suspend_commands_pending
    ON provider_suspend_commands (tenant_id, event_id)
    WHERE status = 'pending';
ALTER TABLE provider_suspend_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_suspend_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY provider_suspend_commands_isolation ON provider_suspend_commands
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON provider_suspend_commands TO trstctl_app;
