-- migrate: no-transaction
-- Add the indexed result read without a write-blocking index build on a populated projection.
CREATE INDEX CONCURRENTLY IF NOT EXISTS identity_transitions_issuance_result_idx
    ON identity_transitions (tenant_id, identity_id, idempotency_key)
    WHERE event_type = 'identity.issued' AND from_state = 'requested'
      AND to_state = 'issued' AND idempotency_key <> '';
