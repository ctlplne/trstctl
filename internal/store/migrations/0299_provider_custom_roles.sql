-- A90: arbitrary custom Provider operator roles.
--
-- The Provider plane knew two roles, admin and operator, pinned by a CHECK on
-- provider_operators.role. A Provider admin can now define further roles as
-- named subsets of the Provider permission vocabulary; they are recorded as
-- immutable provider.role.upserted / provider.role.deleted authority events
-- and projected here. The CHECK goes so an operator row can carry a custom
-- role name; existing rows keep admin or operator unchanged.
CREATE TABLE IF NOT EXISTS provider_roles (
    tenant_id   uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    name        text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    permissions text[]      NOT NULL DEFAULT '{}'::text[],
    created_by  text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, name)
);

ALTER TABLE provider_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_roles FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS provider_roles_isolation ON provider_roles;
CREATE POLICY provider_roles_isolation ON provider_roles
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON provider_roles TO trstctl_app;

ALTER TABLE provider_operators DROP CONSTRAINT IF EXISTS provider_operators_role_check;
