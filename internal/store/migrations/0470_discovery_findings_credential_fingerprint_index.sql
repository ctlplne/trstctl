-- SPDX-License-Identifier: BUSL-1.1
-- migrate: no-transaction
-- A172-L1: a leaked secret that holds a credential a secret store also holds
-- records that credential's fingerprint in metadata.credential_fingerprint,
-- and the findings fingerprint filter matches it beside the fingerprint
-- column, so the filter reaches the leak without scanning the tenant's
-- findings.
-- online-safe: CONCURRENTLY indexes the populated findings read model without blocking writes.
CREATE INDEX CONCURRENTLY IF NOT EXISTS discovery_findings_credential_fingerprint_idx
    ON discovery_findings (tenant_id, (metadata->>'credential_fingerprint'), id)
    WHERE metadata->>'credential_fingerprint' IS NOT NULL;
