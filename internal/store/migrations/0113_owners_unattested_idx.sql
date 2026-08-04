-- migrate: no-transaction
-- The unowned queue's index (epic I1).
--
-- online-safe: CONCURRENTLY, so building it does not take an ACCESS EXCLUSIVE
-- lock on a populated owners table. The console reads this on every load, and
-- without it the unowned queue degrades into a sequential scan of every owner
-- in the tenant — which is precisely the estate size where the queue matters.
--
-- Separate from 0112 because CREATE INDEX CONCURRENTLY cannot run inside a
-- transaction, and 0112's ALTER TABLE should stay transactional.
--
-- NULLS FIRST matches the query's intent: an owner nobody has EVER attested is
-- the most urgent row, and it should sort to the top rather than to the end.
CREATE INDEX CONCURRENTLY IF NOT EXISTS owners_unattested_idx
    ON owners (tenant_id, ownership_verified_at NULLS FIRST);
