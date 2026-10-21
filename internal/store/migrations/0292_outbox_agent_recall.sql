-- A32: a paused migration run recalls the agent work it has published. A
-- recalled job is not claimable, a lease on it cannot be extended, and a result
-- for it is retained only as a late receipt; resuming the run clears the recall.
-- Runtime claim state like the lease columns themselves: not event payload, but
-- set from the run's projection transaction so replay reproduces it.
-- No index: every reader already filters on the claim columns' indexes and
-- the recall predicate narrows those rows further (SCHEMA-006 keeps this
-- migration online-safe on a populated outbox).
ALTER TABLE outbox
    ADD COLUMN agent_recalled_at timestamptz;
