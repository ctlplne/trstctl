-- SPDX-License-Identifier: BUSL-1.1

-- M2-L3: the incident a misuse finding opens for its API token, until an
-- operator closes it; later findings for the token attach to the open one.
-- Projected from misuse.incident.opened and misuse.incident.closed (AN-2).
-- Core schema, licensed projection, like misuse_findings.
CREATE TABLE IF NOT EXISTS misuse_incidents (
    tenant_id       uuid        NOT NULL,
    incident_id     text        NOT NULL CHECK (incident_id <> '' AND length(incident_id) <= 64),
    credential_id   text        NOT NULL CHECK (credential_id <> ''),
    principal       text        NOT NULL DEFAULT '',
    opened_by_finding text      NOT NULL DEFAULT '',
    status          text        NOT NULL CHECK (status IN ('open', 'closed')),
    opened_at       timestamptz NOT NULL,
    closed_at       timestamptz,
    closed_by       text        NOT NULL DEFAULT '',
    resolution      text        NOT NULL DEFAULT '' CHECK (resolution IN ('', 'token_revoked', 'expected_use', 'other')),
    note            text        NOT NULL DEFAULT '',
    event_sequence  bigint      NOT NULL CHECK (event_sequence >= 0),
    PRIMARY KEY (tenant_id, incident_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS misuse_incidents_one_open_per_token
    ON misuse_incidents (tenant_id, credential_id) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS misuse_incidents_recent
    ON misuse_incidents (tenant_id, opened_at DESC, incident_id DESC);
ALTER TABLE misuse_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE misuse_incidents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS misuse_incidents_isolation ON misuse_incidents;
CREATE POLICY misuse_incidents_isolation ON misuse_incidents
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON misuse_incidents TO trstctl_app;
