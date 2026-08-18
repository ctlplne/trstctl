-- 0159_secret_rotation_schedule_registration_identity.sql -- bind scheduler
-- authority to one canonical tenant registration.
--
-- Version-2 scheduler receivers did not name the tenant.registered event that
-- owned them. They remain readable privacy/recovery evidence, but are inert: a
-- version-3 producer derives a lifecycle-scoped outer key and can never claim a
-- version-2 row. SQL must not invent the canonical event ID held in history.

ALTER TABLE secret_rotation_schedule_ticks
    ADD COLUMN identity_version smallint NOT NULL DEFAULT 2,
    ADD COLUMN tenant_registration_event_id text NOT NULL DEFAULT '',
    ADD COLUMN tenant_registration_event_sequence bigint NOT NULL DEFAULT 0;

ALTER TABLE secret_rotation_schedule_tick_rows
    ADD COLUMN identity_version smallint NOT NULL DEFAULT 2,
    ADD COLUMN tenant_registration_event_id text NOT NULL DEFAULT '',
    ADD COLUMN tenant_registration_event_sequence bigint NOT NULL DEFAULT 0;

ALTER TABLE secret_rotation_schedule_commands
    ADD COLUMN identity_version smallint NOT NULL DEFAULT 2,
    ADD COLUMN tenant_registration_event_id text NOT NULL DEFAULT '',
    ADD COLUMN tenant_registration_event_sequence bigint NOT NULL DEFAULT 0;

ALTER TABLE secret_rotation_schedule_ticks
    ADD CONSTRAINT secret_rotation_schedule_ticks_registration_chk CHECK (
        (identity_version = 2 AND tenant_registration_event_id = '' AND
         tenant_registration_event_sequence = 0)
        OR
        (identity_version = 3 AND tenant_registration_event_id <> '' AND
         tenant_registration_event_sequence > 0)
    ),
    ADD CONSTRAINT secret_rotation_schedule_ticks_registration_uq UNIQUE
        (tenant_id, idempotency_key, identity_version,
         tenant_registration_event_id, tenant_registration_event_sequence);

ALTER TABLE secret_rotation_schedule_tick_rows
    ADD CONSTRAINT secret_rotation_schedule_tick_rows_registration_chk CHECK (
        (identity_version = 2 AND tenant_registration_event_id = '' AND
         tenant_registration_event_sequence = 0)
        OR
        (identity_version = 3 AND tenant_registration_event_id <> '' AND
         tenant_registration_event_sequence > 0)
    );

ALTER TABLE secret_rotation_schedule_tick_rows
    DROP CONSTRAINT secret_rotation_schedule_tick_rows_tick_fk;
ALTER TABLE secret_rotation_schedule_tick_rows
    ADD CONSTRAINT secret_rotation_schedule_tick_rows_tick_fk
        FOREIGN KEY (
            tenant_id, idempotency_key, identity_version,
            tenant_registration_event_id, tenant_registration_event_sequence
        )
        REFERENCES secret_rotation_schedule_ticks (
            tenant_id, idempotency_key, identity_version,
            tenant_registration_event_id, tenant_registration_event_sequence
        )
        ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE secret_rotation_schedule_commands
    DROP CONSTRAINT secret_rotation_schedule_commands_due_uq;
ALTER TABLE secret_rotation_schedule_commands
    ADD CONSTRAINT secret_rotation_schedule_commands_due_uq UNIQUE
        (tenant_id, identity_version, tenant_registration_event_sequence,
         schedule_id, due_at),
    ADD CONSTRAINT secret_rotation_schedule_commands_registration_chk CHECK (
        (identity_version = 2 AND tenant_registration_event_id = '' AND
         tenant_registration_event_sequence = 0)
        OR
        (identity_version = 3 AND tenant_registration_event_id <> '' AND
         tenant_registration_event_sequence > 0)
    );

-- A pre-upgrade cursor can name only a version-2 tick. Release it so it cannot
-- delay a version-3 lifecycle-scoped claim. The old rows remain inert evidence.
UPDATE secret_rotation_schedule_scan_cursors
   SET active_tick_key = '', active_tick_binding = '',
       lease_token = '', lease_until = NULL,
       updated_at = clock_timestamp()
 WHERE active_tick_key <> '';

CREATE INDEX secret_rotation_schedule_commands_registration_claim_idx
    ON secret_rotation_schedule_commands (
        tenant_id, tenant_registration_event_sequence,
        status, lease_until, due_at, schedule_id
    );

GRANT INSERT (
    identity_version, tenant_registration_event_id,
    tenant_registration_event_sequence
) ON secret_rotation_schedule_commands TO trstctl_app;

COMMENT ON COLUMN secret_rotation_schedule_ticks.tenant_registration_event_id IS
    'Canonical tenant.registered event ID owning this aggregate tick; v2 rows are empty and permanently inert.';
COMMENT ON COLUMN secret_rotation_schedule_commands.tenant_registration_event_id IS
    'Canonical tenant.registered event ID retained as audited evidence and matched on replay; the DB-verifiable sequence, not this spelling, scopes v3 identities.';
