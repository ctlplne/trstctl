-- I4: recent enrollment refusals, collapsed by their typed diagnosis.
--
-- A diagnosis is operational tenant data: even without a subject name, its
-- timestamp and retry count disclose when another estate is failing. The old
-- process-global map therefore crossed the AN-1 boundary and disappeared on
-- restart. This table is only the read projection; enrollment.diagnostic.observed
-- events remain the AN-2 source of truth and rebuild it after loss.
-- Recent event identities make the projection idempotent across the inline
-- command projection and the asynchronous log tail. They are bounded per
-- tenant below; the event log, not this dedup window, remains permanent.
CREATE TABLE enrollment_diagnostic_observations (
    tenant_id       uuid        NOT NULL,
    source_event_id text        NOT NULL,
    event_sequence  bigint      NOT NULL,
    protocol        text        NOT NULL,
    step            text        NOT NULL,
    cause           text        NOT NULL,
    observed_at     timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, source_event_id),
    CONSTRAINT enrollment_diagnostic_observations_sequence_positive CHECK (event_sequence > 0)
);

ALTER TABLE enrollment_diagnostic_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_diagnostic_observations FORCE ROW LEVEL SECURITY;

CREATE POLICY enrollment_diagnostic_observations_tenant_isolation ON enrollment_diagnostic_observations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX enrollment_diagnostic_observations_recent_idx
    ON enrollment_diagnostic_observations (tenant_id, event_sequence DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON enrollment_diagnostic_observations TO trstctl_app;

CREATE TABLE enrollment_diagnostics (
    tenant_id       uuid        NOT NULL,
    protocol        text        NOT NULL,
    step            text        NOT NULL,
    cause           text        NOT NULL,
    summary         text        NOT NULL,
    remediation     text        NOT NULL DEFAULT '',
    actionable      boolean     NOT NULL,
    observed_at     timestamptz NOT NULL,
    observation_count bigint    NOT NULL,
    source_event_id text        NOT NULL,
    event_sequence  bigint      NOT NULL,
    PRIMARY KEY (tenant_id, protocol, step, cause),
    CONSTRAINT enrollment_diagnostics_count_positive CHECK (observation_count > 0),
    CONSTRAINT enrollment_diagnostics_event_sequence_positive CHECK (event_sequence > 0)
);

ALTER TABLE enrollment_diagnostics ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_diagnostics FORCE ROW LEVEL SECURITY;

CREATE POLICY enrollment_diagnostics_tenant_isolation ON enrollment_diagnostics
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX enrollment_diagnostics_recent_idx
    ON enrollment_diagnostics (tenant_id, observed_at DESC, event_sequence DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON enrollment_diagnostics TO trstctl_app;

COMMENT ON TABLE enrollment_diagnostics IS
    'Per-tenant bounded projection of enrollment.diagnostic.observed events (epic I4); the event log is authoritative.';

COMMENT ON TABLE enrollment_diagnostic_observations IS
    'Bounded per-tenant idempotency window for enrollment diagnostic projection events; not an independent source of truth.';
