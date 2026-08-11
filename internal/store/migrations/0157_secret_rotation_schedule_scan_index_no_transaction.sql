-- migrate: no-transaction
-- 0157_secret_rotation_schedule_scan_index_no_transaction.sql -- online UUID-ring scan index.
--
-- secret_rotation_schedules predates this migration and may be populated. Build
-- its fairness index concurrently so the upgrade does not block schedule writes.
-- DROP makes a retry safe if PostgreSQL left an INVALID index after an interrupted
-- concurrent build.

DROP INDEX CONCURRENTLY IF EXISTS secret_rotation_schedules_tenant_scan_idx;

CREATE INDEX CONCURRENTLY secret_rotation_schedules_tenant_scan_idx
    ON secret_rotation_schedules (tenant_id, id, next_run_at)
    WHERE enabled;
