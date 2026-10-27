-- A180: external observers and what they saw at endpoints.
--
-- An external observer (probectl or any monitor) reports what it saw at an
-- endpoint; trstctl matches each observation to the certificate the endpoint is
-- expected to serve and keeps it as evidence independent of its own agents'
-- verification. Both tables are projections of observer.* and
-- observation.recorded events and rebuild from the event log.
CREATE TABLE IF NOT EXISTS external_observers (
    tenant_id      uuid        NOT NULL,
    id             uuid        NOT NULL,
    name           text        NOT NULL CHECK (name <> ''),
    events_url     text        NOT NULL DEFAULT '',
    credential_ref text        NOT NULL DEFAULT '',
    enabled        boolean     NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name)
);
ALTER TABLE external_observers ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_observers FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS external_observers_isolation ON external_observers;
CREATE POLICY external_observers_isolation ON external_observers
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON external_observers TO trstctl_app;

CREATE TABLE IF NOT EXISTS external_observations (
    tenant_id            uuid        NOT NULL,
    id                   uuid        NOT NULL,
    observer_id          uuid        NOT NULL,
    endpoint             text        NOT NULL CHECK (endpoint <> ''),
    vantage              text        NOT NULL DEFAULT '',
    observed_at          timestamptz NOT NULL,
    reachable            boolean     NOT NULL,
    health               text        NOT NULL CHECK (health IN ('healthy', 'degraded', 'unhealthy', 'unknown')),
    served_fingerprint   text        NOT NULL DEFAULT '',
    chain_fingerprints   text[]      NOT NULL DEFAULT '{}',
    detail               text        NOT NULL DEFAULT '',
    -- expected_fingerprint is what trstctl expected this endpoint to serve when
    -- the observation arrived; empty when no deployment names the endpoint.
    expected_fingerprint text        NOT NULL DEFAULT '',
    verdict              text        NOT NULL CHECK (verdict IN ('match', 'mismatch', 'unreachable', 'unexpected')),
    recorded_at          timestamptz NOT NULL,
    event_sequence       bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id),
    CHECK (reachable OR (served_fingerprint = '' AND verdict = 'unreachable')),
    FOREIGN KEY (tenant_id, observer_id) REFERENCES external_observers (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS external_observations_by_served
    ON external_observations (tenant_id, served_fingerprint) WHERE served_fingerprint <> '';
CREATE INDEX IF NOT EXISTS external_observations_by_expected
    ON external_observations (tenant_id, expected_fingerprint) WHERE expected_fingerprint <> '';
CREATE INDEX IF NOT EXISTS external_observations_by_endpoint
    ON external_observations (tenant_id, endpoint, observed_at DESC);
ALTER TABLE external_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_observations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS external_observations_isolation ON external_observations;
CREATE POLICY external_observations_isolation ON external_observations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON external_observations TO trstctl_app;
