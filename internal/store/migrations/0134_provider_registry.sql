-- Durable provider-plane tenant registry and break-glass ledger (epic L3).
--
-- The provider plane's Store defaulted to an in-memory implementation: a
-- provider provisioned a customer, saw it in the console, and lost the whole
-- customer list on the next deploy — the registry a provider runs their
-- business from, gone silently. These two tables make it durable.
--
-- They are PROVIDER-global: the provider plane manages many customer tenants
-- and lists them all, a cross-tenant read no single tenant's RLS context can
-- serve, so the plane reaches them through the store's system pool (the same
-- RLS-bypassing path the core tenant registry is read by). But per AN-1 and the
-- ISO-1 isolation probe every tenant-identified table still carries ENABLE +
-- FORCE row-level security keyed on its tenant column, exactly like the core
-- `tenants` table: a tenant session may see only its own row, and what lets the
-- provider read across tenants is the deliberate system-pool path, not the
-- fence's absence.

CREATE TABLE provider_tenants (
    tenant_id  uuid PRIMARY KEY,
    slug       text NOT NULL UNIQUE,
    name       text NOT NULL,
    status     text NOT NULL, -- 'active' | 'suspended' | 'offboarded'
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

ALTER TABLE provider_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_tenants FORCE ROW LEVEL SECURITY;

-- A tenant session sees only its own registry row; the provider plane reads
-- every customer through the system pool. Same shape as the core tenants
-- policy: a NULL GUC denies all rows (fail closed).
CREATE POLICY provider_tenants_isolation ON provider_tenants
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON provider_tenants TO trstctl_app;

-- The break-glass grant ledger. tenant_id is the CUSTOMER the grant is scoped
-- to; RLS is keyed on it so a customer can see grants against their own
-- tenancy, and the provider plane reads a grant by its id across tenants
-- through the system pool.
CREATE TABLE provider_breakglass_grants (
    id             text PRIMARY KEY,
    tenant_id      uuid NOT NULL,
    operator_id    text NOT NULL,
    operator_email text NOT NULL DEFAULT '',
    reason         text NOT NULL DEFAULT '',
    requested_at   timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    consented_at   timestamptz,
    consented_by   text NOT NULL DEFAULT '',
    denied_at      timestamptz,
    denied_by      text NOT NULL DEFAULT '',
    revoked_at     timestamptz,
    use_count      integer NOT NULL DEFAULT 0
);

ALTER TABLE provider_breakglass_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_breakglass_grants FORCE ROW LEVEL SECURITY;

CREATE POLICY provider_breakglass_grants_isolation ON provider_breakglass_grants
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX provider_breakglass_grants_tenant_idx
    ON provider_breakglass_grants (tenant_id, requested_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON provider_breakglass_grants TO trstctl_app;
