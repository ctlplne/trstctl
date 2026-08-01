-- Discovery coverage rollup: one row per discovery source carrying its kind
-- and latest completed-run state, projected from discovery.source.upserted and
-- discovery.run.completed. The coverage API classifies these rows against the
-- observability envelopes in internal/cbom/coverage at read time (freshness is
-- a read-time judgment, never baked into a stored row), so the deployment can
-- say which asset classes are OBSERVED, which are observable but unobserved
-- and why, and which no configured source can ever see.

CREATE TABLE discovery_coverage (
    tenant_id         uuid NOT NULL,
    source_id         uuid NOT NULL,
    source_kind       text NOT NULL,
    source_name       text NOT NULL DEFAULT '',
    last_run_status   text NOT NULL DEFAULT '',
    last_completed_at timestamptz,
    event_sequence    bigint NOT NULL DEFAULT 0 CHECK (event_sequence >= 0),
    PRIMARY KEY (tenant_id, source_id),
    FOREIGN KEY (tenant_id, source_id) REFERENCES discovery_sources (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX discovery_coverage_kind_idx
    ON discovery_coverage (tenant_id, source_kind, source_id);

ALTER TABLE discovery_coverage ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_coverage FORCE ROW LEVEL SECURITY;

CREATE POLICY discovery_coverage_isolation ON discovery_coverage
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON discovery_coverage TO trstctl_app;
