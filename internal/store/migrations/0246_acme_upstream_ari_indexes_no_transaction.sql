-- migrate: no-transaction
-- The outbox can be large. Fence this new receiver key and scan existing
-- externally issued leaves without blocking normal delivery or inventory use.
DROP INDEX CONCURRENTLY IF EXISTS outbox_external_ari_idempotency_idx;
CREATE UNIQUE INDEX CONCURRENTLY outbox_external_ari_idempotency_idx
    ON outbox (tenant_id, idempotency_key)
    WHERE destination = 'external-ca.ari.fetch';
DROP INDEX CONCURRENTLY IF EXISTS certificates_external_ari_candidates_idx;
CREATE INDEX CONCURRENTLY certificates_external_ari_candidates_idx
    ON certificates (tenant_id, status, not_after, id)
    WHERE source LIKE 'external-ca:%';
