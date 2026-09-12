-- migrate: no-transaction
-- Read an exact asynchronous preview result without scanning tenant history.
CREATE INDEX CONCURRENTLY IF NOT EXISTS connector_delivery_receipts_tenant_key_id_idx
    ON connector_delivery_receipts (tenant_id, idempotency_key, id);
