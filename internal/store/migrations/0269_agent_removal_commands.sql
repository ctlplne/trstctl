-- Agent authority ends when this first-writer command commits, before its
-- immutable source event is published or projected. Pending rows retain the
-- exact event for recovery; completed rows retain public selectors only.
CREATE TABLE agent_removal_commands (
    tenant_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('offboard', 'cert')),
    serial text NOT NULL DEFAULT '',
    fingerprint text NOT NULL DEFAULT '',
    event_id uuid NOT NULL,
    event_time timestamptz NOT NULL,
    event_actor jsonb,
    event_payload bytea,
    payload_sha256 char(64),
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, agent_id, kind, serial, fingerprint),
    UNIQUE (tenant_id, event_id),
    CHECK ((kind = 'offboard' AND serial = '' AND fingerprint = '') OR
           (kind = 'cert' AND (serial <> '' OR fingerprint <> ''))),
    CHECK ((status = 'pending' AND event_payload IS NOT NULL AND
            payload_sha256 ~ '^[0-9a-f]{64}$') OR
           (status = 'completed' AND event_payload IS NULL AND
            payload_sha256 IS NULL AND event_actor IS NULL))
);

ALTER TABLE agent_removal_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_removal_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_removal_commands_isolation ON agent_removal_commands
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_removal_commands TO trstctl_app;
CREATE INDEX agent_removal_commands_pending
    ON agent_removal_commands (tenant_id, updated_at, agent_id)
    WHERE status = 'pending';
