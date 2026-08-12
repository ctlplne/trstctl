-- migrate: no-transaction
-- AUD-44 / epic I1: bound the steady-state re-attestation cadence scan.
--
-- online-safe: CONCURRENTLY keeps owner writes available while PostgreSQL scans
-- the already-populated owners table. This is deliberately separate from 0168
-- because CREATE INDEX CONCURRENTLY cannot run inside a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS owners_reattestation_due_idx
    ON owners (tenant_id, ownership_verified_at, ownership_reattestation_requested_for);
