-- migrate: no-transaction
-- A244: the certificate inventory asks, per identity, whether anything saw an
-- endpoint present the delivered certificate; a clean verification is looked
-- up by its observed fingerprint.
CREATE INDEX CONCURRENTLY IF NOT EXISTS endpoint_verifications_observed_fingerprint_idx
    ON endpoint_verifications (tenant_id, observed_fingerprint, last_checked_at DESC)
    WHERE reached AND mismatch = '';
