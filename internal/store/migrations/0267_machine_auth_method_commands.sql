-- A method disable must deny new machine logins before its event is published.
-- The latest command is independent backup state; the event stream remains the
-- source of truth for the operator read model. Pending enable also denies login.
CREATE TABLE machine_auth_method_commands (
    tenant_id uuid NOT NULL,
    method_name text NOT NULL,
    target_disabled boolean NOT NULL,
    event_id uuid NOT NULL,
    event_time timestamptz NOT NULL,
    event_actor jsonb,
    event_payload bytea,
    payload_sha256 char(64),
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, method_name),
    UNIQUE (tenant_id, event_id),
    CHECK (method_name <> ''),
    CHECK ((status = 'pending' AND event_payload IS NOT NULL AND
            payload_sha256 ~ '^[0-9a-f]{64}$') OR
           (status = 'completed' AND event_payload IS NULL AND
            payload_sha256 IS NULL AND event_actor IS NULL))
);

ALTER TABLE machine_auth_method_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE machine_auth_method_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY machine_auth_method_commands_isolation
    ON machine_auth_method_commands
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON machine_auth_method_commands TO trstctl_app;

-- Replay order comes from JetStream sequence, never a host wall clock. A
-- legacy event may have a future timestamp; later commands still win.
ALTER TABLE machine_auth_method_overrides
    ADD COLUMN last_event_sequence bigint NOT NULL DEFAULT 0;
