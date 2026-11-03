-- A243: secret migrations. A run is a value-free plan of an export moving into
-- a project (assessed), the import of its values as new secret versions while
-- the export's system stays each secret's writer (staged), the consumers' first
-- reads from the store, the hand-over of each secret's writing to the store (cut
-- over), credentials the export could not carry reissued instead of migrated,
-- and a rollback manifest. No value is kept here. Projection of the
-- secret.migration.* events.
CREATE TABLE IF NOT EXISTS secret_migrations (
    tenant_id           uuid        NOT NULL,
    id                  uuid        NOT NULL,
    project             text        NOT NULL CHECK (project <> ''),
    state               text        NOT NULL CHECK (state IN ('assessed', 'staged', 'cut-over', 'rolled-back')),
    digest              text        NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    plan                jsonb       NOT NULL CHECK (jsonb_typeof(plan) = 'object'),
    accepted_open       jsonb       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(accepted_open) = 'array'),
    created_by          text        NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL,
    staged_at           timestamptz,
    staged_by           text        NOT NULL DEFAULT '',
    permissions_applied jsonb       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(permissions_applied) = 'array'),
    cut_over_at         timestamptz,
    cut_over_by         text        NOT NULL DEFAULT '',
    rolled_back_at      timestamptz,
    rolled_back_by      text        NOT NULL DEFAULT '',
    updated_at          timestamptz NOT NULL,
    event_sequence      bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id)
);
-- One row per object a run wrote: the version it found (the rollback manifest),
-- the version it wrote, and who writes the secret now: the export's system
-- ("source") until cutover, then the store ("store"). A reissued credential is
-- the store's from the start and is never "migrated".
CREATE TABLE IF NOT EXISTS secret_migration_objects (
    tenant_id        uuid    NOT NULL,
    migration_id     uuid    NOT NULL,
    name             text    NOT NULL CHECK (name <> ''),
    outcome          text    NOT NULL CHECK (outcome IN ('migrated', 'reissued')),
    prior_version    integer NOT NULL CHECK (prior_version >= 0),
    version          integer NOT NULL CHECK (version > 0),
    writer           text    NOT NULL CHECK (writer IN ('source', 'store')),
    rollback         text    NOT NULL DEFAULT '' CHECK (rollback IN ('', 'restored', 'deleted', 'kept')),
    rollback_version integer NOT NULL DEFAULT 0 CHECK (rollback_version >= 0),
    event_sequence   bigint  NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, migration_id, name)
);
CREATE INDEX IF NOT EXISTS secret_migration_objects_source_writer
    ON secret_migration_objects (tenant_id, name) WHERE writer = 'source' AND rollback = '';
-- A consumer's first read of a migrated secret from the store, as its subject.
CREATE TABLE IF NOT EXISTS secret_migration_consumer_reads (
    tenant_id      uuid        NOT NULL,
    migration_id   uuid        NOT NULL,
    consumer       text        NOT NULL CHECK (consumer <> ''),
    name           text        NOT NULL CHECK (name <> ''),
    version        integer     NOT NULL CHECK (version > 0),
    reader         text        NOT NULL CHECK (reader <> ''),
    read_at        timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, migration_id, consumer, name)
);
ALTER TABLE secret_migrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_migrations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secret_migrations_isolation ON secret_migrations;
CREATE POLICY secret_migrations_isolation ON secret_migrations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON secret_migrations TO trstctl_app;
ALTER TABLE secret_migration_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_migration_objects FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secret_migration_objects_isolation ON secret_migration_objects;
CREATE POLICY secret_migration_objects_isolation ON secret_migration_objects
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON secret_migration_objects TO trstctl_app;
ALTER TABLE secret_migration_consumer_reads ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_migration_consumer_reads FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secret_migration_consumer_reads_isolation ON secret_migration_consumer_reads;
CREATE POLICY secret_migration_consumer_reads_isolation ON secret_migration_consumer_reads
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON secret_migration_consumer_reads TO trstctl_app;
-- A migration writes its versions through the versioned-batch reservation.
ALTER TABLE application_secret_import_batches
    DROP CONSTRAINT IF EXISTS application_secret_import_batches_operation_check;
ALTER TABLE application_secret_import_batches
    ADD CONSTRAINT application_secret_import_batches_operation_check
    CHECK (operation IN ('import', 'promotion', 'restore', 'migration'));
