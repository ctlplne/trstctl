-- migrate: no-transaction
-- 0193_application_secret_owner_index_no_transaction.sql — online lookup path
-- for the optional owner relationship added by migration 0192.
--
-- This file intentionally runs outside a transaction: PostgreSQL requires that
-- for concurrent index construction.

CREATE INDEX CONCURRENTLY IF NOT EXISTS secret_store_tenant_owner_idx
    ON secret_store (tenant_id, owner_id)
    WHERE owner_id IS NOT NULL;
