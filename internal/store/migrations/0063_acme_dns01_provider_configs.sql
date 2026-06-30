-- Served ACME DNS-01 provider configuration (TRACE-003). This table is a
-- tenant-scoped projection of acme.dns01.provider_config.* events. It stores
-- provider metadata and secret references only; raw provider credentials remain
-- in the sealed secret store.

CREATE TABLE acme_dns01_provider_configs (
    id                uuid PRIMARY KEY,
    tenant_id         uuid NOT NULL,
    name              text NOT NULL,
    provider          text NOT NULL,
    zone              text NOT NULL DEFAULT '',
    challenge_domain  text NOT NULL DEFAULT '',
    delegation_target text NOT NULL DEFAULT '',
    credential_refs   jsonb NOT NULL DEFAULT '{}',
    config            jsonb NOT NULL DEFAULT '{}',
    caa_issuer_domain text NOT NULL DEFAULT '',
    allowed_methods   text[] NOT NULL DEFAULT '{}',
    allow_wildcards   boolean NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE INDEX acme_dns01_provider_configs_provider_idx
    ON acme_dns01_provider_configs (tenant_id, provider, id);

ALTER TABLE acme_dns01_provider_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE acme_dns01_provider_configs FORCE  ROW LEVEL SECURITY;

CREATE POLICY acme_dns01_provider_configs_isolation ON acme_dns01_provider_configs
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON acme_dns01_provider_configs TO trstctl_app;
