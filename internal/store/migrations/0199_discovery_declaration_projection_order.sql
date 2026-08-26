-- Bind mutable discovery declarations to the immutable event that most recently
-- projected them. The API projects served writes inline while the durable tail
-- applies the same JetStream event at least once. A sequence plus event ID lets
-- both writers converge without turning a genuinely different same-sequence
-- payload into a silent last-writer-wins update.

ALTER TABLE discovery_segments
    ADD COLUMN projection_event_id text,
    ADD COLUMN projection_event_sequence bigint NOT NULL DEFAULT 0
        CHECK (projection_event_sequence >= 0);

ALTER TABLE discovery_sources
    ADD COLUMN projection_event_id text,
    ADD COLUMN projection_event_sequence bigint NOT NULL DEFAULT 0
        CHECK (projection_event_sequence >= 0);

COMMENT ON COLUMN discovery_segments.projection_event_id IS
    'Immutable event ID that most recently projected the declaration; NULL only for rows predating event-backed segment writes.';
COMMENT ON COLUMN discovery_segments.projection_event_sequence IS
    'JetStream sequence of the latest projected declaration event; orders inline, tail, replay, and rebuild writers.';
COMMENT ON COLUMN discovery_sources.projection_event_id IS
    'Immutable event ID that most recently projected the source declaration; NULL only for pre-migration/direct fixture rows.';
COMMENT ON COLUMN discovery_sources.projection_event_sequence IS
    'JetStream sequence of the latest projected source event; orders inline, tail, replay, and rebuild writers.';
