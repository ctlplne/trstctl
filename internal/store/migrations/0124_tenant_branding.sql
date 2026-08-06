-- L3/AUD-14: durable white-label branding.
--
-- Branding was in memory. A provider configured their brand, saw it resolve,
-- and lost it on the next deploy — SILENTLY. Their customers went back to the
-- default product name with nothing in the running system saying why. For a
-- white-label feature, that is the product failing quietly: the whole value is
-- that the customer never sees our name, and a restart undoes it.
--
-- One row per tenant, plus a single provider-wide row for the brand shown
-- before any tenant is known (the login screen a customer meets on a custom
-- domain).

CREATE TABLE IF NOT EXISTS tenant_branding (
    tenant_id       uuid PRIMARY KEY,
    product_name    text NOT NULL DEFAULT '',
    logo_data_uri   text NOT NULL DEFAULT '',
    login_message   text NOT NULL DEFAULT '',
    token_overrides jsonb NOT NULL DEFAULT '{}'::jsonb,
    email_from_name text NOT NULL DEFAULT '',
    email_footer    text NOT NULL DEFAULT '',
    -- The custom domain this tenant's brand answers on. Unique because two
    -- tenants claiming one host is not a branding question, it is an identity
    -- question — and resolving it "somehow" would show one customer another's
    -- name.
    custom_domain   text NOT NULL DEFAULT '',
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS tenant_branding_domain_key
    ON tenant_branding (custom_domain) WHERE custom_domain <> '';

ALTER TABLE tenant_branding ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_branding FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_branding_tenant_isolation ON tenant_branding;
CREATE POLICY tenant_branding_tenant_isolation ON tenant_branding
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_branding TO trstctl_app;
