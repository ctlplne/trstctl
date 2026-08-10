-- migrate: no-transaction
--
-- AUD-45: stable source event identity makes ownership-conflict projection
-- idempotent under relay-result retry and full event replay. This table is live
-- and may be large, so build the uniqueness guard without blocking writers.
-- IF NOT EXISTS makes a retry safe if the process exits after PostgreSQL
-- finishes the index but before the migration ledger row is committed.

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS owner_conflicts_source_event_key
    ON owner_ownership_conflicts (tenant_id, source_event_id, field)
    WHERE source_event_id IS NOT NULL;
