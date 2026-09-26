-- A session lock disappears on connection/process loss; an accepted remote
-- request does not. Keep independent delivery tokens until the same invocation
-- proves completion or proves that receiver IO never started. Retry counters,
-- lease expiry and another invocation's success cannot clear these tokens.
ALTER TABLE outbox ADD COLUMN receiver_pending_ids uuid[] NOT NULL DEFAULT '{}';

-- Older incomplete deliveries and multi-attempt successes cannot prove that
-- every former receiver stopped. This sentinel means unknown legacy work, not
-- a fabricated attempt identity. A single successful delivery is terminal.
UPDATE outbox
SET receiver_pending_ids = ARRAY['00000000-0000-0000-0000-000000000226'::uuid]
WHERE attempts > 0 AND (status <> 'delivered' OR attempts > 1);
