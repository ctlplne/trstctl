-- migrate: no-transaction
--
-- The claim indexes for the agent job ledger (epic A1), built concurrently.
--
-- The outbox is the busiest table in the deployment: every state change with an
-- external effect writes to it, and the dispatch workers read from it
-- continuously. A plain CREATE INDEX takes ACCESS EXCLUSIVE for the whole build,
-- which on a large outbox stalls issuance, revocation, notification and every
-- other effect at once. That is not a lock worth taking for an index.
--
-- So these are CONCURRENTLY, which needs its own transaction-free migration.
-- The trade is that a failed build leaves an INVALID index behind rather than
-- rolling back; that is recoverable by hand (DROP INDEX, re-run) and is the right
-- side of the trade for a table this hot. The claim columns landed separately in
-- 0098 precisely so that failure mode cannot strand a half-applied schema.

-- The claim scan: "unclaimed or expired entries for these destinations, oldest
-- first". Partial on the pending set, which is what a queue actually is —
-- delivered history is the overwhelming majority of rows and is never scanned
-- for claims.
CREATE INDEX CONCURRENTLY IF NOT EXISTS outbox_agent_claimable_idx
    ON outbox (tenant_id, destination, id)
    WHERE status = 'pending' AND delivered_at IS NULL;

-- The lease sweep: "which claims have lapsed". An agent that dies mid-job stops
-- extending its lease, and this is how the entry gets back to the queue instead
-- of staying stuck to a machine that is gone.
CREATE INDEX CONCURRENTLY IF NOT EXISTS outbox_agent_claim_expiry_idx
    ON outbox (claim_expires_at)
    WHERE claimed_by_agent_id IS NOT NULL AND claim_completed_at IS NULL;
