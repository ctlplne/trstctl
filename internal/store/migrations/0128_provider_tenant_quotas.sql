-- L2: durable per-customer quotas.
--
-- The quota checker was installed on every deployment and consulted a store
-- whose durable implementation returned the zero quota unconditionally — so a
-- provider "setting" a limit had it silently discarded, and the limit read as
-- enforced right up until the customer sailed past it. A cap that does not
-- survive a restart, or was never stored at all, is not a cap; it is a UI.
--
-- Columns are NULLABLE and NULL means the ABSENCE of a limit, never a limit of
-- zero. A customer nobody capped creates freely; a customer capped at zero is
-- refused. Those are opposite instructions and the schema must not let one
-- read as the other.
--
-- RLS, like the meters (0122): the row carries tenant_id, so AN-1 applies and
-- ISO-1 demands ENABLE + FORCE. What stops a tenant raising their own cap is
-- the served surface — quota writes go through the provider plane behind the
-- per-customer delegation gate — not the fence's absence.

CREATE TABLE IF NOT EXISTS provider_tenant_quotas (
    tenant_id               uuid PRIMARY KEY,
    max_agents              integer,
    max_tenants             integer,
    max_certificates_stored integer,
    max_secrets_stored      integer,
    updated_by              text,
    updated_at              timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE provider_tenant_quotas ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_tenant_quotas FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS provider_tenant_quotas_tenant_isolation ON provider_tenant_quotas;
CREATE POLICY provider_tenant_quotas_tenant_isolation ON provider_tenant_quotas
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON provider_tenant_quotas TO trstctl_app;

COMMENT ON TABLE provider_tenant_quotas IS
    'Durable per-customer resource limits (epic L2). NULL means no limit; writes come only through the provider plane behind the delegation gate.';
