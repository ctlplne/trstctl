-- SPDX-License-Identifier: BUSL-1.1

-- Older read-model snapshots omit these columns. A null list represents
-- absent policy and restores through the existing typed snapshot loader.
ALTER TABLE workload_attester_trust_sources
    ADD COLUMN IF NOT EXISTS allowed_owner_ids text[],
    ADD COLUMN IF NOT EXISTS allowed_repository_ids text[];

COMMENT ON COLUMN workload_attester_trust_sources.allowed_owner_ids IS
    'Allowed signed GitHub repository_owner_id strings in the configured issuer namespace.';
COMMENT ON COLUMN workload_attester_trust_sources.allowed_repository_ids IS
    'Allowed signed GitHub repository_id strings in the configured issuer namespace.';
