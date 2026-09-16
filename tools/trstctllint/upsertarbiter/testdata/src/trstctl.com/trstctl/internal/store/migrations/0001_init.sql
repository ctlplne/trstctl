-- fixture schema for the upsertarbiter rule
CREATE TABLE dual (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    UNIQUE (tenant_id, name)
);
CREATE TABLE single (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE named (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    key text NOT NULL,
    CONSTRAINT named_pkey PRIMARY KEY (id),
    CONSTRAINT named_tenant_key UNIQUE (tenant_id, key)
);
CREATE UNIQUE INDEX indexed_tenant_ref ON indexed (tenant_id, ref);
CREATE TABLE indexed (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    ref text NOT NULL
);

-- A primary key moved onto the tenant-scoped columns (the agents shape): after the
-- move only (tenant_id, id) is unique, so an upsert arbitrating on it is complete.
CREATE TABLE moved (id uuid PRIMARY KEY, tenant_id uuid NOT NULL, name text NOT NULL);
ALTER TABLE moved ADD CONSTRAINT moved_tenant_id_id_key UNIQUE (tenant_id, id);
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS moved_tenant_id_id_primary_uq ON moved (tenant_id, id);
ALTER TABLE moved DROP CONSTRAINT moved_pkey, ADD CONSTRAINT moved_pkey PRIMARY KEY USING INDEX moved_tenant_id_id_primary_uq;
-- A primary key re-pinned onto a new identity column (the enrollment_diagnostics shape).
CREATE TABLE repinned (tenant_id uuid NOT NULL, protocol text NOT NULL, diagnostic_id text, PRIMARY KEY (tenant_id, protocol));
ALTER TABLE repinned ALTER COLUMN diagnostic_id SET NOT NULL, DROP CONSTRAINT repinned_pkey, ADD PRIMARY KEY (tenant_id, diagnostic_id);
-- A dropped unique index no longer counts.
CREATE TABLE unindexed (id uuid PRIMARY KEY, tenant_id uuid NOT NULL, name text NOT NULL);
CREATE UNIQUE INDEX unindexed_name_idx ON unindexed (tenant_id, name);
DROP INDEX unindexed_name_idx;

CREATE TABLE triple (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    alias text NOT NULL UNIQUE,
    UNIQUE (tenant_id, name)
);
