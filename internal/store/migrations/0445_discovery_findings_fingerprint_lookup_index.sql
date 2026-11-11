-- SPDX-License-Identifier: BUSL-1.1
-- migrate: no-transaction
-- A172-L2: the findings list filters by fingerprint across kinds and pages by
-- id, so every finding that names one certificate or key is reached without
-- scanning the tenant's findings.
-- online-safe: CONCURRENTLY indexes the populated findings read model without blocking writes.
CREATE INDEX CONCURRENTLY IF NOT EXISTS discovery_findings_fingerprint_idx
    ON discovery_findings (tenant_id, fingerprint, id);
