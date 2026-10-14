-- Cancellation is authority removal. Commit its first-writer command before
-- publishing the immutable event so a broker/SQL gap cannot admit a signer.
CREATE TABLE ca_ceremony_cancel_commands (
    tenant_id uuid NOT NULL,
    ceremony_id uuid NOT NULL,
    event_id text NOT NULL,
    event_time timestamptz NOT NULL,
    event_actor jsonb,
    event_payload bytea,
    payload_sha256 char(64),
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, ceremony_id),
    UNIQUE (tenant_id, event_id),
    CHECK ((status = 'pending' AND event_payload IS NOT NULL AND
            payload_sha256 ~ '^[0-9a-f]{64}$') OR
           (status = 'completed' AND event_payload IS NULL AND
            payload_sha256 IS NULL AND event_actor IS NULL))
);
ALTER TABLE ca_ceremony_cancel_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE ca_ceremony_cancel_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY ca_ceremony_cancel_commands_isolation
    ON ca_ceremony_cancel_commands
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON ca_ceremony_cancel_commands TO trstctl_app;
CREATE INDEX ca_ceremony_cancel_commands_pending
    ON ca_ceremony_cancel_commands (tenant_id, created_at, ceremony_id)
    WHERE status = 'pending';
