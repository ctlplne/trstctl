-- 0290_secret_static_rotation_commands.sql — durable static-provider rotation
-- commands (A14/A15).
--
-- One row is the projected state of one static-credential rotation: the
-- provider role it rotates, the application secret that publishes the
-- credential, the predecessor reference to retire, and the phase the durable
-- worker has reached (queued → staged → cutover → verified → completed, or a
-- terminal rolled_back / rollback_failed / failed / retire_pending). The staged
-- credential and the predecessor value are envelope-encrypted under the tenant
-- key domain (AN-8) so a restart resumes exactly where the worker stopped
-- without a second provider call. Every transition is an immutable event; this
-- table is its projection.

CREATE TABLE IF NOT EXISTS secret_static_rotation_commands (
    tenant_id            uuid NOT NULL,
    id                   uuid NOT NULL,
    tenant_epoch         text NOT NULL,
    provider             text NOT NULL,
    provider_type        text NOT NULL DEFAULT '',
    secret_key           text NOT NULL,
    old_ref              text NOT NULL,
    new_ref              text NOT NULL DEFAULT '',
    phase                text NOT NULL,
    expected_version     integer NOT NULL DEFAULT 0,
    result_version       integer NOT NULL DEFAULT 0,
    restored_version     integer NOT NULL DEFAULT 0,
    sealed_new           bytea,
    sealed_old           bytea,
    verify_mode          text NOT NULL DEFAULT '',
    error                text NOT NULL DEFAULT '',
    idempotency_key_digest text NOT NULL,
    request_binding      text NOT NULL,
    schedule_id          uuid,
    outbox_id            bigint,
    created_at           timestamptz NOT NULL,
    updated_at           timestamptz NOT NULL,
    terminal_at          timestamptz,
    PRIMARY KEY (tenant_id, id)
);

ALTER TABLE secret_static_rotation_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_static_rotation_commands FORCE  ROW LEVEL SECURITY;

CREATE POLICY secret_static_rotation_commands_isolation ON secret_static_rotation_commands
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX IF NOT EXISTS secret_static_rotation_commands_key_idx
    ON secret_static_rotation_commands (tenant_id, secret_key, created_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON secret_static_rotation_commands TO trstctl_app;
