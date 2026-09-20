-- PCAS-08: idempotency for succession orchestration (claim 6 / INV-4). A
-- succession recorded under an Idempotency-Key is unique per tenant, so a retried
-- orchestration job returns the original record instead of minting again.
ALTER TABLE succession_records ADD COLUMN idempotency_key text NOT NULL DEFAULT '';

CREATE UNIQUE INDEX succession_records_idem_uq
    ON succession_records (tenant_id, idempotency_key)
    WHERE idempotency_key <> '';
