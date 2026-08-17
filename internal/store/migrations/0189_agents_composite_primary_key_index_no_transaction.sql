-- migrate: no-transaction
-- AGENT-RACE-001: build the tenant-scoped agents primary-key index without
-- blocking writes while PostgreSQL scans an installed fleet table. Migration
-- 0190 performs the short catalog-only primary-key attachment after this index is
-- valid. The existing UNIQUE (tenant_id, id) remains in place because historical
-- relay foreign keys depend on that named constraint.

-- online-safe: concurrent index build keeps agent heartbeat and renewal projections writable.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS agents_tenant_id_id_primary_uq
    ON agents (tenant_id, id);
