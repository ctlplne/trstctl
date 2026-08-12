-- AUD-40 / epic H2: durable, tenant-isolated CA migration wave aggregate.
-- The immutable migration.run.recorded stream is the authority; this table is
-- only its latest replayable read projection.
CREATE TABLE migration_runs (
    tenant_id          uuid        NOT NULL,
    id                 uuid        NOT NULL,
    status             text        NOT NULL,
    aggregate          jsonb       NOT NULL,
    last_event_sequence bigint     NOT NULL,
    created_at         timestamptz NOT NULL,
    updated_at         timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT migration_runs_status_chk
        CHECK (status IN ('planned', 'running', 'paused', 'halted', 'rolling_back', 'rolled_back', 'complete')),
    CONSTRAINT migration_runs_sequence_chk CHECK (last_event_sequence > 0),
    CONSTRAINT migration_runs_aggregate_chk CHECK (jsonb_typeof(aggregate) = 'object')
);

ALTER TABLE migration_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE migration_runs FORCE ROW LEVEL SECURITY;

CREATE POLICY migration_runs_isolation ON migration_runs
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX migration_runs_updated_idx
    ON migration_runs (tenant_id, updated_at DESC, id);

GRANT SELECT, INSERT, UPDATE, DELETE ON migration_runs TO trstctl_app;

COMMENT ON TABLE migration_runs IS
    'Tenant-isolated latest projection of executable trust-before-leaf migration runs (epic H2).';
