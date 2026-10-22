-- SPDX-License-Identifier: BUSL-1.1

-- A62: the enrolled binary's own executor census, reported on agent.heartbeat
-- v4 and projected here for the console. NULL reported_at means an older agent
-- cannot report it and the console falls back to this server build's census.
-- The census authorizes nothing: certificate roles and the server's job-kind
-- census still gate every claim.
ALTER TABLE agents
    ADD COLUMN executors jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN executors_reported_at timestamptz;

ALTER TABLE agents
    ADD CONSTRAINT agents_executors_shape_check
        CHECK (jsonb_typeof(executors) = 'object');
