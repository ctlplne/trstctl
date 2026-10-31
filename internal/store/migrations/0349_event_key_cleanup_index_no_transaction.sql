-- migrate: no-transaction
-- Keep the exact completed event-key sweep independent of ordinary outbox size.
-- Recreate only this owned index so an interrupted concurrent build can retry.
DROP INDEX CONCURRENTLY IF EXISTS outbox_event_key_cleanup_idx;
CREATE INDEX CONCURRENTLY outbox_event_key_cleanup_idx ON outbox (id)
    WHERE destination = 'eventprivacy.destroy'
      AND COALESCE(NULLIF(effect_lane, ''), destination) = destination
      AND required_agent_role = 'control_plane'
      AND required_agent_id IS NULL
      AND status = 'delivered'
      AND cardinality(receiver_pending_ids) = 0;
