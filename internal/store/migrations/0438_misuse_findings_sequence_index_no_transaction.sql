-- migrate: no-transaction
-- M2-L1: GET /api/v1/misuse/findings lists a tenant's misuse findings newest
-- first, a page at a time below the last event sequence it returned.
CREATE INDEX CONCURRENTLY IF NOT EXISTS misuse_findings_tenant_sequence_idx
    ON misuse_findings (tenant_id, event_sequence DESC);
