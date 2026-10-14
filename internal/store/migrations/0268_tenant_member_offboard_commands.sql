-- An offboard claim denies a subject before its event is published or projected.
-- The pending exact event survives backup; completion scrubs PII but retains the
-- source sequence needed to reject late bearer projections after a rehire.
CREATE TABLE tenant_member_offboard_commands (
    tenant_id uuid NOT NULL,
    subject_ref char(64) NOT NULL,
    event_id uuid NOT NULL,
    event_time timestamptz NOT NULL,
    event_schema_version integer NOT NULL,
    event_actor jsonb,
    event_payload bytea,
    payload_sha256 char(64),
    last_event_sequence bigint NOT NULL DEFAULT 0,
    status text NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, subject_ref),
    UNIQUE (tenant_id, event_id),
    CHECK (subject_ref ~ '^[0-9a-f]{64}$'),
    CHECK (last_event_sequence >= 0),
    CHECK ((status = 'pending' AND event_payload IS NOT NULL AND
            payload_sha256 ~ '^[0-9a-f]{64}$') OR
           (status = 'completed' AND last_event_sequence > 0 AND
            event_payload IS NULL AND payload_sha256 IS NULL AND event_actor IS NULL))
);

ALTER TABLE tenant_member_offboard_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_member_offboard_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_member_offboard_commands_isolation
    ON tenant_member_offboard_commands
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_member_offboard_commands TO trstctl_app;
CREATE INDEX tenant_member_offboard_commands_pending
    ON tenant_member_offboard_commands (tenant_id, updated_at, subject_ref)
    WHERE status = 'pending';

-- An older duplicate offboard/upsert event may be delivered after a rehire.
-- Source sequence, rather than the host clock, decides the member read model.
ALTER TABLE tenant_members ADD COLUMN last_event_sequence bigint NOT NULL DEFAULT 0;
