-- The RLS-subject role that tenant-scoped operations assume (see
-- Store.WithTenant). It holds only the table grants below; superusers bypass
-- RLS, so tenant queries SET ROLE to this role to be subject to it. Roles are
-- cluster-global, so create it only if absent: this keeps the migration
-- re-runnable across databases in one cluster (and idempotent under retry).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trstctl_app') THEN
        CREATE ROLE trstctl_app NOLOGIN;
    END IF;
END
$$;

-- Tenants read model (the Tenant entity). tenant_id is the tenant's own id; per
-- AN-1 every table carries tenant_id.
CREATE TABLE tenants (
    tenant_id  uuid PRIMARY KEY,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    event_seq  bigint NOT NULL DEFAULT 0
);

-- AN-1: isolation is enforced by row-level security, not application code.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;

-- A session may see only rows for its current tenant. When the GUC is unset the
-- expression is NULL, so the policy denies all rows (fail closed).
CREATE POLICY tenants_isolation ON tenants
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON tenants TO trstctl_app;
