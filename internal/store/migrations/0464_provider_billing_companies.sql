-- MSP-2: the Provider plane maps each customer to its company in each billing
-- or PSA system the deployment pushes usage to (provider.billing_sync.targets).
-- A customer's closed, signed usage periods go only to the company its own
-- mapping names, and one company in one target belongs to one customer: the
-- UNIQUE (target_id, external_company_id) index is the database's half of
-- "never one customer's counts to another's company" (the command checks it
-- first, under the Provider authority fence, so no event can be refused here).
-- The table is the projection of provider.tenant.billing_company.set and
-- .cleared and rebuilds from the Provider event history.
CREATE TABLE IF NOT EXISTS provider_billing_companies (
    tenant_id           uuid        NOT NULL,
    target_id           text        NOT NULL CHECK (target_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    external_company_id text        NOT NULL CHECK (length(btrim(external_company_id)) > 0 AND length(external_company_id) <= 128),
    mapped_by           text        NOT NULL DEFAULT '',
    mapped_at           timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, target_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS provider_billing_companies_company_idx
    ON provider_billing_companies (target_id, external_company_id);

ALTER TABLE provider_billing_companies ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_billing_companies FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS provider_billing_companies_tenant_isolation ON provider_billing_companies;
CREATE POLICY provider_billing_companies_tenant_isolation ON provider_billing_companies
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON provider_billing_companies TO trstctl_app;

COMMENT ON TABLE provider_billing_companies IS
    'MSP-2: each customer''s company in each configured billing target; written only by the Provider authority projection.';
