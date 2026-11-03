-- A247: rehearsals of failure scenarios. A scenario is a saved, multi-step
-- failure (approval resumption, target outage, renewal failure, revoked
-- credential, stale policy, restore, retry) with its candidate, data set and
-- the effect each step should have. A run replays it in one mode: a static
-- preview, a mocked rehearsal, a sandbox execution against non-production
-- targets with generated credentials, or a live observation of real receipts.
-- Each run records the tool and connector versions, the candidate, the data
-- set's digest, the expected effects and what was observed, and its label is
-- its mode's: a mock success is never labeled live. Projections of
-- rehearsal.scenario.saved, rehearsal.run.started and rehearsal.run.completed.
CREATE TABLE IF NOT EXISTS rehearsal_scenarios (
    tenant_id      uuid        NOT NULL,
    id             uuid        NOT NULL,
    name           text        NOT NULL CHECK (length(btrim(name)) > 0 AND length(name) <= 200),
    kind           text        NOT NULL CHECK (kind IN ('approval_resumption', 'target_outage', 'renewal_failure',
                                                        'revoked_credential', 'stale_policy', 'restore', 'retry')),
    revision       bigint      NOT NULL CHECK (revision > 0),
    candidate      jsonb       NOT NULL,
    data_set       jsonb       NOT NULL,
    steps          jsonb       NOT NULL,
    created_by     text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE IF NOT EXISTS rehearsal_runs (
    tenant_id          uuid        NOT NULL,
    id                 uuid        NOT NULL,
    scenario_id        uuid        NOT NULL,
    scenario_revision  bigint      NOT NULL CHECK (scenario_revision > 0),
    mode               text        NOT NULL CHECK (mode IN ('static_preview', 'mocked_rehearsal',
                                                            'sandbox_execution', 'live_observation')),
    status             text        NOT NULL CHECK (status IN ('running', 'completed')),
    verdict            text        NOT NULL DEFAULT '' CHECK (verdict IN ('', 'matched', 'diverged', 'blocked')),
    label              text        NOT NULL DEFAULT '',
    tool_version       text        NOT NULL,
    connector_versions jsonb       NOT NULL DEFAULT '{}',
    candidate          jsonb       NOT NULL,
    data_set_digest    text        NOT NULL,
    expected           jsonb       NOT NULL,
    observations       jsonb       NOT NULL DEFAULT '[]',
    detail             text        NOT NULL DEFAULT '',
    started_by         text        NOT NULL DEFAULT '',
    started_at         timestamptz NOT NULL,
    completed_at       timestamptz,
    event_sequence     bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS rehearsal_runs_scenario_idx ON rehearsal_runs (tenant_id, scenario_id, started_at DESC);
ALTER TABLE rehearsal_scenarios ENABLE ROW LEVEL SECURITY;
ALTER TABLE rehearsal_scenarios FORCE ROW LEVEL SECURITY;
ALTER TABLE rehearsal_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE rehearsal_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rehearsal_scenarios_isolation ON rehearsal_scenarios;
CREATE POLICY rehearsal_scenarios_isolation ON rehearsal_scenarios
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
DROP POLICY IF EXISTS rehearsal_runs_isolation ON rehearsal_runs;
CREATE POLICY rehearsal_runs_isolation ON rehearsal_runs
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON rehearsal_scenarios, rehearsal_runs TO trstctl_app;
