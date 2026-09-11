-- The durable event envelope orders rollback queue/result facts. A lagging tail
-- must not replace a newer inline receipt. Nullable for older snapshot row shapes;
-- zero/NULL means no post-upgrade event has yet established the cursor.
ALTER TABLE connector_delivery_receipts
    ADD COLUMN latest_event_sequence bigint DEFAULT 0 CHECK (latest_event_sequence >= 0);

-- The normal warm-boot check should stay cheap after all legacy rows are rebuilt.
CREATE INDEX connector_rollback_receipts_unordered
    ON connector_delivery_receipts (tenant_id, id)
    WHERE destination = 'connector.rollback' AND coalesce(latest_event_sequence, 0) = 0;
