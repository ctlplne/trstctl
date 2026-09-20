-- migrate: no-transaction
-- SPDX-License-Identifier: BUSL-1.1

-- AUD-65 joins current graph rows to event-projected action bindings by tenant
-- and finding. The campaign table is already live, so build the partial index
-- concurrently; IF NOT EXISTS keeps a retried no-transaction migration safe.
-- online-safe: CONCURRENTLY avoids blocking campaign evidence writes on the
-- populated finding projection while PostgreSQL builds the lookup structure.
CREATE INDEX CONCURRENTLY IF NOT EXISTS pqc_migration_campaign_findings_readiness_binding_idx
    ON pqc_migration_campaign_findings (tenant_id, finding_id, campaign_id)
    WHERE readiness_digest IS NOT NULL AND readiness_digest <> '';
