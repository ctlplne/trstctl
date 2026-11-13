-- SPDX-License-Identifier: BUSL-1.1

-- A245-L2: a host agent's count, right after a verified deploy or renewal, of
-- the established connections on the listener's port and how many a process
-- older than the deploy holds; projected from
-- connector.listener_sessions.observed (AN-2). The revocation report reads the
-- newest count per target for whether the sessions opened with a replaced
-- certificate are gone.
CREATE TABLE IF NOT EXISTS listener_session_observations (
    tenant_id      uuid        NOT NULL,
    id             text        NOT NULL CHECK (id <> '' AND length(id) <= 200),
    identity_id    uuid,
    target_id      text        NOT NULL CHECK (target_id <> ''),
    target         text        NOT NULL CHECK (target <> ''),
    fingerprint    text        NOT NULL CHECK (fingerprint <> ''),
    port           integer     NOT NULL CHECK (port BETWEEN 1 AND 65535),
    established    integer     NOT NULL CHECK (established >= 0),
    held_by_older  integer     NOT NULL CHECK (held_by_older >= 0),
    unattributed   integer     NOT NULL CHECK (unattributed >= 0),
    since          timestamptz NOT NULL,
    checked_at     timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence >= 0),
    PRIMARY KEY (tenant_id, id),
    CHECK (held_by_older + unattributed <= established),
    CHECK (since <= checked_at)
);
CREATE INDEX IF NOT EXISTS listener_session_observations_identity
    ON listener_session_observations (tenant_id, identity_id, target, checked_at DESC);
ALTER TABLE listener_session_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE listener_session_observations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS listener_session_observations_isolation ON listener_session_observations;
CREATE POLICY listener_session_observations_isolation ON listener_session_observations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON listener_session_observations TO trstctl_app;
