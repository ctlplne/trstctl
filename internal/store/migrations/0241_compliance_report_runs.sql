-- Scheduled reports retain a replayable receipt and a bound archive locator.
-- Signed report bytes live in the configured archive, outside replay payloads.
CREATE TABLE compliance_report_runs (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    schedule_id uuid NOT NULL,
    due_at timestamptz NOT NULL,
    framework text NOT NULL,
    report_type text NOT NULL,
    status text NOT NULL CHECK (status IN ('queued', 'retrying', 'failed', 'completed')),
    retry_generation integer NOT NULL CHECK (retry_generation >= 0),
    attempt integer NOT NULL CHECK (attempt >= 0 AND attempt <= 5),
    next_attempt_at timestamptz,
    error_code text NOT NULL DEFAULT '',
    artifact_ref text NOT NULL DEFAULT '',
    artifact_digest text NOT NULL DEFAULT '',
    completed_at timestamptz,
    event_sequence bigint NOT NULL CHECK (event_sequence > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT compliance_report_runs_schedule_fk FOREIGN KEY (tenant_id, schedule_id)
        REFERENCES compliance_report_schedules (tenant_id, id),
    CONSTRAINT compliance_report_runs_due_edge_unique UNIQUE (tenant_id, schedule_id, due_at),
    CONSTRAINT compliance_report_runs_artifact_chk CHECK (
        (status = 'completed' AND artifact_ref <> '' AND artifact_digest ~ '^[0-9a-f]{64}$'
         AND completed_at IS NOT NULL AND next_attempt_at IS NULL AND error_code = '')
        OR (status <> 'completed' AND artifact_ref = '' AND artifact_digest = ''
            AND completed_at IS NULL)
    )
);

ALTER TABLE compliance_report_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_report_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY compliance_report_runs_isolation ON compliance_report_runs
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));
CREATE INDEX compliance_report_runs_due_idx
    ON compliance_report_runs (tenant_id, status, next_attempt_at, due_at);
CREATE INDEX compliance_report_runs_schedule_idx
    ON compliance_report_runs (tenant_id, schedule_id, due_at DESC);
GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_report_runs TO trstctl_app;
