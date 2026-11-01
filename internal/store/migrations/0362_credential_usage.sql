-- M1: when, and from where, each credential was last used, from trstctl's own
-- activity. An API token's authenticated requests are recorded as
-- credential.used (at most one event per token, client network, action and
-- hour, plus doubling counts); each machine login (secrets.session.started)
-- counts as a use of its login method from the workload it attested. Projections
-- rebuilt from the event log. credential_usage_gaps records the windows in
-- which uses could not be recorded, so missing telemetry is never read as
-- non-use.
CREATE TABLE IF NOT EXISTS credential_usage (
    tenant_id      uuid        NOT NULL,
    kind           text        NOT NULL CHECK (kind IN ('api_token', 'machine_auth')),
    credential_id  text        NOT NULL CHECK (credential_id <> ''),
    principal      text        NOT NULL DEFAULT '',
    first_used_at  timestamptz NOT NULL,
    last_used_at   timestamptz NOT NULL CHECK (last_used_at >= first_used_at),
    last_source    text        NOT NULL DEFAULT '',
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, kind, credential_id)
);
ALTER TABLE credential_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_usage FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS credential_usage_isolation ON credential_usage;
CREATE POLICY credential_usage_isolation ON credential_usage
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON credential_usage TO trstctl_app;

CREATE TABLE IF NOT EXISTS credential_usage_sources (
    tenant_id      uuid        NOT NULL,
    kind           text        NOT NULL CHECK (kind IN ('api_token', 'machine_auth')),
    credential_id  text        NOT NULL CHECK (credential_id <> ''),
    source_kind    text        NOT NULL CHECK (source_kind IN ('network', 'attestation')),
    source         text        NOT NULL CHECK (source <> ''),
    first_seen_at  timestamptz NOT NULL,
    last_seen_at   timestamptz NOT NULL CHECK (last_seen_at >= first_seen_at),
    days_seen      integer     NOT NULL CHECK (days_seen >= 1),
    last_day       date        NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, kind, credential_id, source_kind, source)
);
ALTER TABLE credential_usage_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_usage_sources FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS credential_usage_sources_isolation ON credential_usage_sources;
CREATE POLICY credential_usage_sources_isolation ON credential_usage_sources
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON credential_usage_sources TO trstctl_app;

CREATE TABLE IF NOT EXISTS credential_usage_gaps (
    tenant_id      uuid        NOT NULL,
    gap_id         text        NOT NULL CHECK (gap_id <> ''),
    from_at        timestamptz NOT NULL,
    to_at          timestamptz NOT NULL CHECK (to_at >= from_at),
    dropped        bigint      NOT NULL CHECK (dropped > 0),
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, gap_id)
);
ALTER TABLE credential_usage_gaps ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_usage_gaps FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS credential_usage_gaps_isolation ON credential_usage_gaps;
CREATE POLICY credential_usage_gaps_isolation ON credential_usage_gaps
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON credential_usage_gaps TO trstctl_app;
