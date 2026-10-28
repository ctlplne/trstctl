-- A207: tenant custom roles. A tenant's access administrator defines further
-- roles as named subsets of the core permission vocabulary, recorded as
-- immutable access.role.upserted / access.role.deleted events and projected
-- here. A deleted role keeps its row as a tombstone (deleted_at) so a replayed
-- earlier definition cannot bring it back; defining it again clears it.
-- Built-in role names are reserved by the command, not by this table.
CREATE TABLE IF NOT EXISTS tenant_custom_roles (
    tenant_id      uuid        NOT NULL,
    name           text        NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{1,62}$'),
    description    text        NOT NULL DEFAULT '' CHECK (length(description) <= 512),
    permissions    text[]      NOT NULL DEFAULT '{}'::text[],
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    deleted_at     timestamptz,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, name)
);
ALTER TABLE tenant_custom_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_custom_roles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_custom_roles_isolation ON tenant_custom_roles;
CREATE POLICY tenant_custom_roles_isolation ON tenant_custom_roles
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_custom_roles TO trstctl_app;
