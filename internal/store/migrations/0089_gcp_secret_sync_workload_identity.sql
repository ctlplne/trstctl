-- SPDX-License-Identifier: MPL-2.0

-- Extend the existing tenant-scoped workload-identity source with GCP's thin
-- provider encoder. The shared row remains reference-only: no proof or bearer
-- token bytes are persisted.
ALTER TABLE secret_sync_workload_identity_sources
    ADD COLUMN service_account TEXT NOT NULL DEFAULT '';

ALTER TABLE secret_sync_workload_identity_sources
    DROP CONSTRAINT secret_sync_workload_identity_provider_chk,
    DROP CONSTRAINT secret_sync_workload_identity_role_chk;

ALTER TABLE secret_sync_workload_identity_sources
    ADD CONSTRAINT secret_sync_workload_identity_provider_chk
        CHECK (provider IN ('aws', 'gcp')),
    ADD CONSTRAINT secret_sync_workload_identity_provider_config_chk
        CHECK (
            (provider = 'aws'
                AND length(btrim(role_arn)) > 0
                AND length(btrim(service_account)) = 0)
            OR
            (provider = 'gcp'
                AND length(btrim(role_arn)) = 0
                AND (
                    length(btrim(service_account)) = 0
                    OR service_account ~ '^[^[:space:]@]+@[^[:space:]@]+[.]iam[.]gserviceaccount[.]com$'
                ))
        );
