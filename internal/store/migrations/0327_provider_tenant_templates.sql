-- Provider tenant templates.
--
-- A Provider holds its customer tenants to versioned templates of tenant
-- objects (certificate profiles, the lifecycle policy, CA bindings, connector
-- targets, notification channels, member role grants and report schedules).
-- Template versions and each customer's last application are recorded as
-- immutable provider.template.recorded / provider.tenant_template.applied
-- authority events and projected here.
--
-- Templates belong to the Provider: like provider_roles they sit under the
-- fixed Provider authority tenant. A binding names the CUSTOMER it applies to,
-- and its row-level security is keyed on that customer like provider_tenants;
-- the Provider plane reads across customers through the system pool.
CREATE TABLE IF NOT EXISTS provider_tenant_templates (
    tenant_id   uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    template_id text        NOT NULL,
    version     integer     NOT NULL,
    name        text        NOT NULL,
    baseline    jsonb       NOT NULL,
    digest      text        NOT NULL,
    recorded_by text        NOT NULL DEFAULT '',
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, template_id, version)
);

ALTER TABLE provider_tenant_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_tenant_templates FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS provider_tenant_templates_isolation ON provider_tenant_templates;
CREATE POLICY provider_tenant_templates_isolation ON provider_tenant_templates
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON provider_tenant_templates TO trstctl_app;

CREATE TABLE IF NOT EXISTS provider_tenant_template_bindings (
    tenant_id   uuid        PRIMARY KEY,
    template_id text        NOT NULL,
    version     integer     NOT NULL,
    digest      text        NOT NULL,
    complete    boolean     NOT NULL,
    results     jsonb       NOT NULL DEFAULT '[]'::jsonb,
    applied_by  text        NOT NULL DEFAULT '',
    applied_at  timestamptz NOT NULL
);

ALTER TABLE provider_tenant_template_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_tenant_template_bindings FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS provider_tenant_template_bindings_isolation ON provider_tenant_template_bindings;
CREATE POLICY provider_tenant_template_bindings_isolation ON provider_tenant_template_bindings
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX IF NOT EXISTS provider_tenant_template_bindings_template_idx
    ON provider_tenant_template_bindings (template_id, tenant_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON provider_tenant_template_bindings TO trstctl_app;
