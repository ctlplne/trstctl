-- migrate: no-transaction
-- Discovery must use the immutable issuer, including leaves whose mutable
-- inventory source was later changed to "issued" or "import".
DROP INDEX CONCURRENTLY IF EXISTS certificates_external_ari_candidates_idx;
CREATE INDEX CONCURRENTLY certificates_external_ari_candidates_idx
    ON certificates (tenant_id, status, not_after, id)
    WHERE issuing_external_ca_id <> '';
