-- Lifecycle rotation evidence can be written inline while the ordered tail is
-- applying the same immutable stream. Producer timestamps are not an ordering
-- primitive: federation preserves a peer's clock and local clocks can step or
-- tie. Keep the first and latest LOCAL event sequence used to fold each natural
-- (tenant_id, outbox_id) run so replay decisions follow JetStream order.
--
-- Existing rows remain NULL/NULL. The first post-upgrade observation adopts a
-- sequence without rewriting historical data; a full event rebuild naturally
-- fills both columns from the source-of-truth log.

ALTER TABLE lifecycle_rotation_runs
    ADD COLUMN first_event_sequence bigint,
    ADD COLUMN latest_event_sequence bigint,
    ADD CONSTRAINT lifecycle_rotation_runs_event_sequence_shape_chk CHECK (
        (first_event_sequence IS NULL AND latest_event_sequence IS NULL)
        OR
        (first_event_sequence > 0 AND latest_event_sequence >= first_event_sequence)
    );
