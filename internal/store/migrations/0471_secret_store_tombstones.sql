-- A236-L4: a deleted application secret is kept as a tombstone, with its sealed
-- version history, so it can be restored until the deleted-secret retention
-- window (secrets.deleted_retention) ends; the retention sweep then removes it.
-- Like secret_store and secret_store_versions this is independent, backed-up
-- PostgreSQL state written in the same transaction as the event's projection:
-- deleting a secret moves its rows here, and restoring it (the "undelete"
-- action, event secret.undeleted) moves them back. Values stay sealed and bound
-- to (tenant, name) as AAD, so a restored secret opens exactly as before. One
-- tombstone per name: deleting a secret recreated under a deleted name replaces
-- the older tombstone.
CREATE TABLE IF NOT EXISTS secret_store_tombstones (
    tenant_id        uuid        NOT NULL,
    name             text        NOT NULL CHECK (length(btrim(name)) > 0),
    owner_id         uuid,
    version          integer     NOT NULL CHECK (version > 0),
    created_at       timestamptz NOT NULL,
    deleted_at       timestamptz NOT NULL,
    deleted_event_id uuid        NOT NULL,
    PRIMARY KEY (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS secret_store_tombstones_deleted_at_idx
    ON secret_store_tombstones (deleted_at);
ALTER TABLE secret_store_tombstones ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_store_tombstones FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secret_store_tombstones_isolation ON secret_store_tombstones;
CREATE POLICY secret_store_tombstones_isolation ON secret_store_tombstones
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON secret_store_tombstones TO trstctl_app;

CREATE TABLE IF NOT EXISTS secret_store_tombstone_versions (
    tenant_id              uuid        NOT NULL,
    name                   text        NOT NULL,
    version                integer     NOT NULL CHECK (version > 0),
    sealed                 bytea       NOT NULL,
    written_at             timestamptz NOT NULL,
    recovered_from_version integer,
    PRIMARY KEY (tenant_id, name, version),
    FOREIGN KEY (tenant_id, name) REFERENCES secret_store_tombstones (tenant_id, name) ON DELETE CASCADE
);
ALTER TABLE secret_store_tombstone_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_store_tombstone_versions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secret_store_tombstone_versions_isolation ON secret_store_tombstone_versions;
CREATE POLICY secret_store_tombstone_versions_isolation ON secret_store_tombstone_versions
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON secret_store_tombstone_versions TO trstctl_app;

-- The mutation receipt admits the restore: it returns the secret at the version
-- it had when deleted (result_version > 0). Existing rows hold the four earlier
-- actions, which the checks still admit, so they are added NOT VALID.
ALTER TABLE application_secret_mutation_receipts
    DROP CONSTRAINT IF EXISTS application_secret_mutation_receipts_action_check;
ALTER TABLE application_secret_mutation_receipts
    ADD CONSTRAINT application_secret_mutation_receipts_action_check
        CHECK (action IN ('create', 'rotate', 'recover', 'delete', 'undelete')) NOT VALID;
ALTER TABLE application_secret_mutation_receipts
    DROP CONSTRAINT IF EXISTS application_secret_mutation_receipts_check;
ALTER TABLE application_secret_mutation_receipts
    ADD CONSTRAINT application_secret_mutation_receipts_check
        CHECK ((action = 'delete' AND result_version = 0) OR
               (action IN ('create', 'rotate', 'recover', 'undelete') AND result_version > 0)) NOT VALID;
