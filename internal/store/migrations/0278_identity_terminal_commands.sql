-- A terminal lifecycle command must deny a queued signer before its event is
-- appended. This receiver commits independently of the projection/outbox tx.
CREATE TABLE identity_terminal_commands (
    tenant_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    event_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type IN ('identity.revoked', 'identity.retired')),
    event_time timestamptz NOT NULL,
    event_schema_version integer NOT NULL CHECK (event_schema_version > 0),
    event_payload bytea,
    payload_sha256 char(64),
    request_binding char(64) NOT NULL CHECK (request_binding ~ '^[0-9a-f]{64}$'),
    target_state text NOT NULL CHECK (target_state IN ('revoked', 'retired')),
    status text NOT NULL DEFAULT 'pending',
    projected_sequence bigint,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, identity_id),
    UNIQUE (tenant_id, event_id),
    CHECK ((status = 'pending' AND event_payload IS NOT NULL AND
            payload_sha256 ~ '^[0-9a-f]{64}$' AND projected_sequence IS NULL) OR
           (status = 'completed' AND event_payload IS NULL AND
            payload_sha256 IS NULL AND projected_sequence > 0))
);
CREATE INDEX identity_terminal_commands_pending
    ON identity_terminal_commands (tenant_id, identity_id) WHERE status = 'pending';
ALTER TABLE identity_terminal_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_terminal_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_terminal_commands_isolation ON identity_terminal_commands
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON identity_terminal_commands TO trstctl_app;

-- A later revoked -> retired command can replace the current fence without
-- erasing the first terminal event's immutable outcome.
CREATE TABLE identity_terminal_receipts (
    tenant_id uuid NOT NULL,
    event_id uuid NOT NULL,
    identity_id uuid NOT NULL,
    event_type text NOT NULL,
    request_binding char(64) NOT NULL CHECK (request_binding ~ '^[0-9a-f]{64}$'),
    payload_sha256 char(64) NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    target_state text NOT NULL CHECK (target_state IN ('revoked', 'retired')),
    projected_sequence bigint NOT NULL CHECK (projected_sequence > 0),
    completed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX identity_terminal_receipts_identity
    ON identity_terminal_receipts (tenant_id, identity_id, projected_sequence DESC);
ALTER TABLE identity_terminal_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_terminal_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_terminal_receipts_isolation ON identity_terminal_receipts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON identity_terminal_receipts TO trstctl_app;
