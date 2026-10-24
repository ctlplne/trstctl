-- SPDX-License-Identifier: BUSL-1.1
-- migrate: no-transaction
-- Owner decision (batch 11): issuance refuses a subject key the tenant has
-- recorded as compromised (CA/B BR 6.1.1.3, condition 4). Every certifying
-- path reads the tenant's keyCompromise revocations, so they get a partial
-- index, built without blocking issuance traffic.
CREATE INDEX CONCURRENTLY IF NOT EXISTS certificates_key_compromise_idx
    ON certificates (tenant_id)
    WHERE revocation_reason = 'keyCompromise';
