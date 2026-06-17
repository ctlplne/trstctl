-- migrate: no-transaction
-- Agent inventory keyset index (SPINE-005).
--
-- GET /api/v1/agents is paginated by (created_at, id), which preserves the
-- endpoint's existing stable order while bounding each request's database scan,
-- allocation, and JSON response size. The tenant prefix keeps the index aligned
-- with RLS-scoped reads (AN-1), and id is the deterministic tie-breaker when many
-- agents register in the same timestamp bucket.
--
-- online-safe: CONCURRENTLY avoids blocking writes on the live agents table; this
-- no-transaction migration is idempotent and safe to retry before the ledger row.

CREATE INDEX CONCURRENTLY IF NOT EXISTS agents_tenant_created_id_idx
    ON agents (tenant_id, created_at, id);
