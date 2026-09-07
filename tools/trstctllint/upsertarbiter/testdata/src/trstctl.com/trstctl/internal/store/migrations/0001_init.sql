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
