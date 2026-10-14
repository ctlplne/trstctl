-- A member role update must narrow an existing browser session before its
-- immutable upsert event can wait behind a failed projection. The pending row
-- carries the exact event for crash recovery; completion scrubs personal data.
CREATE TABLE tenant_member_upsert_commands (
    tenant_id uuid NOT NULL,
    subject_ref char(64) NOT NULL,
    event_id uuid NOT NULL,
    event_time timestamptz NOT NULL,
    event_schema_version integer NOT NULL,
    offboard_event_id uuid,
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
            event_payload IS NULL AND payload_sha256 IS NULL AND event_actor IS NULL) OR
           (status = 'superseded' AND last_event_sequence = 0 AND
            event_payload IS NULL AND payload_sha256 IS NULL AND event_actor IS NULL))
);

ALTER TABLE tenant_member_upsert_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_member_upsert_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_member_upsert_commands_isolation
    ON tenant_member_upsert_commands
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_member_upsert_commands TO trstctl_app;
CREATE INDEX tenant_member_upsert_commands_pending
    ON tenant_member_upsert_commands (tenant_id, updated_at, subject_ref)
    WHERE status = 'pending';
