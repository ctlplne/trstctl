-- migrate: no-transaction
-- Build indexes on the populated honey-token inventory without blocking writers.
-- A failed concurrent build can leave an invalid index. Rebuild each index on
-- retry before the migration ledger records completion.
DROP INDEX CONCURRENTLY IF EXISTS honey_tokens_aws_access_key_idx;
CREATE UNIQUE INDEX CONCURRENTLY honey_tokens_aws_access_key_idx
    ON honey_tokens (aws_access_key_id) WHERE kind = 'aws';
DROP INDEX CONCURRENTLY IF EXISTS honey_tokens_aws_lease_idx;
CREATE UNIQUE INDEX CONCURRENTLY honey_tokens_aws_lease_idx
    ON honey_tokens (tenant_id, aws_lease_id) WHERE kind = 'aws';
DROP INDEX CONCURRENTLY IF EXISTS honey_tokens_tenant_kind_idx;
CREATE INDEX CONCURRENTLY honey_tokens_tenant_kind_idx
    ON honey_tokens (tenant_id, kind, id);
