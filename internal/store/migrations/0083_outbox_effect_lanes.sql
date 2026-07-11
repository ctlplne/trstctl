-- 0083_outbox_effect_lanes.sql -- AN-7 receiver partition for outbox work.
-- migrate: no-transaction
-- Rows with the same external receiver lane remain ordered and circuit-broken
-- together; unrelated connectors/authorities no longer share one global
-- destination lock merely because they use connector.deploy/external-ca.issue.

ALTER TABLE outbox
    ADD COLUMN IF NOT EXISTS effect_lane text NOT NULL DEFAULT '';

-- online-safe: adding the constant default is metadata-only on supported
-- PostgreSQL, and CONCURRENTLY keeps the live outbox writable while the worker
-- lookup index is built. IF NOT EXISTS makes a pre-ledger retry safe.
CREATE INDEX CONCURRENTLY IF NOT EXISTS outbox_effect_lane_processing_idx
    ON outbox (effect_lane, lease_until)
    WHERE status = 'processing';
