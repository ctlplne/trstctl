-- SPDX-License-Identifier: BUSL-1.1
-- migrate: no-transaction
-- The operator's Runs page follows new retries by creation time, with a
-- tenant-scoped (created_at, id) cursor. Keep the existing id index for the
-- legacy API order.
-- Remove an interrupted concurrent build before retrying the migration.
DROP INDEX CONCURRENTLY IF EXISTS discovery_runs_recent_idx;
CREATE INDEX CONCURRENTLY discovery_runs_recent_idx
    ON discovery_runs (tenant_id, created_at DESC, id DESC);
