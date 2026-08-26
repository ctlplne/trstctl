-- F2 recovery: preserve every terminal discovery failure and link a separately
-- queued replacement to the exact run it retries. The nullable column keeps
-- historical events and ordinary runs unchanged. The composite self-reference
-- makes cross-tenant lineage impossible at the storage layer (AN-1).
ALTER TABLE discovery_runs
    ADD COLUMN retry_of_run_id uuid;

ALTER TABLE discovery_runs
    ADD CONSTRAINT discovery_runs_retry_not_self_check
        CHECK (retry_of_run_id IS NULL OR retry_of_run_id <> id) NOT VALID,
    ADD CONSTRAINT discovery_runs_retry_of_run_fk
        FOREIGN KEY (tenant_id, retry_of_run_id)
        REFERENCES discovery_runs (tenant_id, id)
        NOT VALID;

ALTER TABLE discovery_runs
    VALIDATE CONSTRAINT discovery_runs_retry_not_self_check;
ALTER TABLE discovery_runs
    VALIDATE CONSTRAINT discovery_runs_retry_of_run_fk;

COMMENT ON COLUMN discovery_runs.retry_of_run_id IS
    'Immutable tenant-scoped lineage from a replacement run to the terminal unsuccessful run it retries.';
