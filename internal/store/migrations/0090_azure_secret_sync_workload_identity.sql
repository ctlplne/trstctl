-- SPDX-License-Identifier: MPL-2.0

-- Extend the same tenant-scoped workload-identity source with Azure Entra's
-- federated-credential fields. These values are routing policy, not authority:
-- the OIDC assertion and minted bearer token remain outbox-worker-only bytes.
ALTER TABLE secret_sync_workload_identity_sources
    ADD COLUMN azure_tenant_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN client_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN target_scope TEXT NOT NULL DEFAULT '';

ALTER TABLE secret_sync_workload_identity_sources
    DROP CONSTRAINT secret_sync_workload_identity_provider_chk,
    DROP CONSTRAINT secret_sync_workload_identity_provider_config_chk;

ALTER TABLE secret_sync_workload_identity_sources
    ADD CONSTRAINT secret_sync_workload_identity_provider_chk
        CHECK (provider IN ('aws', 'gcp', 'azure')),
    ADD CONSTRAINT secret_sync_workload_identity_provider_config_chk
        CHECK (
            (provider = 'aws'
                AND length(btrim(role_arn)) > 0
                AND length(btrim(service_account)) = 0
                AND length(btrim(azure_tenant_id)) = 0
                AND length(btrim(client_id)) = 0
                AND length(btrim(target_scope)) = 0)
            OR
            (provider = 'gcp'
                AND length(btrim(role_arn)) = 0
                AND length(btrim(azure_tenant_id)) = 0
                AND length(btrim(client_id)) = 0
                AND length(btrim(target_scope)) = 0
                AND (
                    length(btrim(service_account)) = 0
                    OR service_account ~ '^[^[:space:]@]+@[^[:space:]@]+[.]iam[.]gserviceaccount[.]com$'
                ))
            OR
            (provider = 'azure'
                AND length(btrim(role_arn)) = 0
                AND length(btrim(service_account)) = 0
                AND azure_tenant_id ~ '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89AaBb][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$'
                AND client_id ~ '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89AaBb][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$'
                AND target_scope IN (
                    'https://vault.azure.net/.default',
                    'https://vault.azure.cn/.default',
                    'https://vault.usgovcloudapi.net/.default',
                    'https://vault.microsoftazure.de/.default'
                ))
        );
