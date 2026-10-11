-- Incident lists show the newest response first. The ID in an opaque cursor
-- resolves a stable created_at/id boundary even when a run later changes state.
-- migrate: no-transaction
-- online-safe: CONCURRENTLY indexes populated incident read models without blocking writes.
CREATE INDEX CONCURRENTLY IF NOT EXISTS incident_executions_tenant_created_idx
    ON incident_executions (tenant_id, created_at DESC, id DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS incident_fleet_reissuance_runs_tenant_created_idx
    ON incident_fleet_reissuance_runs (tenant_id, created_at DESC, id DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS incident_executions_identity_created_idx
    ON incident_executions (tenant_id, compromised_identity_id, created_at DESC, id DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS incident_fleet_reissuance_runs_issuer_created_idx
    ON incident_fleet_reissuance_runs (tenant_id, issuer_id, created_at DESC, id DESC);
