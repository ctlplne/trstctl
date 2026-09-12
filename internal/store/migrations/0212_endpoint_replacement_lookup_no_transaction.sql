-- migrate: no-transaction
-- Renewal checks an exact original identity for a live successor. Keep that
-- lookup indexed without blocking writes to an existing identity inventory.
CREATE INDEX CONCURRENTLY IF NOT EXISTS identities_endpoint_replacement_idx
    ON identities (tenant_id, (attributes->>'endpoint_replaces_identity_id'), created_at, id)
    WHERE status IN ('issued', 'deployed', 'renewing', 'renewal_failed')
      AND attributes->>'endpoint_replaces_identity_id' IS NOT NULL;
