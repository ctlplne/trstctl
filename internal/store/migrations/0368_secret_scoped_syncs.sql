-- A237: scoped secret sync. A definition names a source scope (a name prefix,
-- e.g. a project environment "<project>/<env>/"), a configured sync target and a
-- destination prefix. Applying a reviewed plan queues the existing per-secret
-- sync jobs for creates and updates and records the destination keys the
-- definition manages; a managed key whose source is gone is deleted only when
-- the definition's delete scope says so (managed keys, or every key under the
-- destination prefix), through its own outbox command.
-- Projections of secret.scoped_sync.defined, .removed, .applied, .key_deleted
-- and .delete_failed.
CREATE TABLE IF NOT EXISTS secret_scoped_syncs (
    tenant_id          uuid        NOT NULL,
    id                 uuid        NOT NULL,
    name               text        NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    source_prefix      text        NOT NULL CHECK (source_prefix <> '' AND right(source_prefix, 1) = '/'),
    target             text        NOT NULL CHECK (target <> ''),
    destination_prefix text        NOT NULL DEFAULT '',
    key_transform      text        NOT NULL DEFAULT 'path' CHECK (key_transform IN ('path', 'env')),
    delete_scope       text        NOT NULL DEFAULT 'none' CHECK (delete_scope IN ('none', 'managed', 'prefix')),
    adopt_existing     boolean     NOT NULL DEFAULT false,
    defined_by         text        NOT NULL DEFAULT '',
    created_at         timestamptz NOT NULL,
    updated_at         timestamptz NOT NULL,
    last_plan_digest   text        NOT NULL DEFAULT '',
    last_applied_at    timestamptz,
    event_sequence     bigint      NOT NULL CHECK (event_sequence > 0),
    -- Names are unique per tenant by the API's check, not a second unique key:
    -- a projection upsert arbitrates on exactly one key (the DP2-046 rule).
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE IF NOT EXISTS secret_scoped_sync_keys (
    tenant_id      uuid        NOT NULL,
    sync_id        uuid        NOT NULL,
    remote_key     text        NOT NULL CHECK (remote_key <> ''),
    source_name    text        NOT NULL DEFAULT '',
    source_version integer     NOT NULL DEFAULT 0 CHECK (source_version >= 0),
    job_id         text        NOT NULL DEFAULT '',
    state          text        NOT NULL CHECK (state IN ('synced', 'delete_queued')),
    delete_id      uuid,
    updated_at     timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, sync_id, remote_key),
    FOREIGN KEY (tenant_id, sync_id) REFERENCES secret_scoped_syncs (tenant_id, id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS secret_scoped_sync_deletes (
    tenant_id      uuid        NOT NULL,
    id             uuid        NOT NULL,
    sync_id        uuid        NOT NULL,
    tenant_epoch   text        NOT NULL CHECK (tenant_epoch <> ''),
    target         text        NOT NULL CHECK (target <> ''),
    remote_key     text        NOT NULL CHECK (remote_key <> ''),
    state          text        NOT NULL CHECK (state IN ('queued', 'deleted', 'failed')),
    error          text        NOT NULL DEFAULT '',
    outbox_id      bigint,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id)
);
ALTER TABLE secret_scoped_syncs ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_scoped_syncs FORCE ROW LEVEL SECURITY;
ALTER TABLE secret_scoped_sync_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_scoped_sync_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE secret_scoped_sync_deletes ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_scoped_sync_deletes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secret_scoped_syncs_isolation ON secret_scoped_syncs;
CREATE POLICY secret_scoped_syncs_isolation ON secret_scoped_syncs
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
DROP POLICY IF EXISTS secret_scoped_sync_keys_isolation ON secret_scoped_sync_keys;
CREATE POLICY secret_scoped_sync_keys_isolation ON secret_scoped_sync_keys
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
DROP POLICY IF EXISTS secret_scoped_sync_deletes_isolation ON secret_scoped_sync_deletes;
CREATE POLICY secret_scoped_sync_deletes_isolation ON secret_scoped_sync_deletes
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON secret_scoped_syncs, secret_scoped_sync_keys, secret_scoped_sync_deletes TO trstctl_app;
