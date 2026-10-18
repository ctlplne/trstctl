-- Durable, tenant-bound first-writer claim for a ceremony effect whose
-- immutable event may be appended before its SQL projection commits. Keep the
-- claim outside derived CA tables so a projection rebuild cannot erase an
-- unappended command and allow cancellation or another effect to win.
CREATE TABLE ca_ceremony_effect_commands (
    tenant_id uuid NOT NULL,
    ceremony_id uuid NOT NULL,
    key_id uuid NOT NULL,
    certificate_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation = 'release_managed_ca_leaf'),
    event_id text NOT NULL,
    event_time timestamptz NOT NULL,
    event_actor bytea,
    actor_sha256 char(64) NOT NULL CHECK (actor_sha256 ~ '^[0-9a-f]{64}$'),
    event_payload bytea,
    payload_sha256 char(64) NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, ceremony_id),
    UNIQUE (tenant_id, event_id),
    UNIQUE (tenant_id, key_id, certificate_id),
    CHECK ((status='pending' AND event_actor IS NOT NULL AND event_payload IS NOT NULL)
        OR (status='completed' AND event_actor IS NULL AND event_payload IS NULL))
);
ALTER TABLE ca_ceremony_effect_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE ca_ceremony_effect_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY ca_ceremony_effect_commands_isolation ON ca_ceremony_effect_commands
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON ca_ceremony_effect_commands TO trstctl_app;
CREATE INDEX ca_ceremony_effect_commands_pending
    ON ca_ceremony_effect_commands (tenant_id, created_at, ceremony_id)
    WHERE status = 'pending';
