-- A92: the licensed tenant band gates the managed-offering create path.
--
-- A hosted tenant provisioned through POST /api/v1/managed-offering/tenants
-- carries its provider relationship in the tenant.registered payload; the
-- read model had no trace of it, so the band was stored and reported but the
-- create path could not count what it had already admitted. The projector now
-- records the managed flag and the provider tenant; existing rows keep false
-- (a tenant registered any other way is not a managed customer).
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS managed_offering boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS provider_tenant_id uuid;
CREATE INDEX IF NOT EXISTS tenants_managed_offering_idx ON tenants (managed_offering) WHERE managed_offering;
