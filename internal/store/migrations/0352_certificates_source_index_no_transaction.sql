-- migrate: no-transaction
-- A161: the AD CS issuer health view counts one external CA's recent issuances
-- (source external-ca:<id>) without scanning a tenant's whole inventory.
-- Recreate only this owned index so an interrupted concurrent build can retry.
DROP INDEX CONCURRENTLY IF EXISTS certificates_source_created_idx;
CREATE INDEX CONCURRENTLY certificates_source_created_idx ON certificates (tenant_id, source, created_at);
