-- SPDX-License-Identifier: BUSL-1.1
-- migrate: no-transaction
-- A121: a certificate's detail lists the private-key files host agents reported
-- whose public key matches it, so findings are reached by kind and fingerprint.
-- online-safe: CONCURRENTLY indexes the populated findings read model without blocking writes.
CREATE INDEX CONCURRENTLY IF NOT EXISTS discovery_findings_kind_fingerprint_idx
    ON discovery_findings (tenant_id, kind, fingerprint);
