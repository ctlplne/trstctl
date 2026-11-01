-- M1's hourly usage counts and M2's misuse findings.
--
-- credential_usage_windows keeps, per API token, client network, action and
-- hour, the largest use count credential.used recorded (1, 2, 4, … 1024): a
-- projection, rebuilt from the event log, pruned per credential to the 30 days
-- before its newest window.
CREATE TABLE IF NOT EXISTS credential_usage_windows (
    tenant_id      uuid        NOT NULL,
    kind           text        NOT NULL CHECK (kind IN ('api_token')),
    credential_id  text        NOT NULL CHECK (credential_id <> ''),
    source         text        NOT NULL CHECK (source <> ''),
    action         text        NOT NULL CHECK (action IN ('api_call', 'secret_read', 'lease_request')),
    window_start   timestamptz NOT NULL,
    max_count      integer     NOT NULL CHECK (max_count >= 1),
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, kind, credential_id, source, action, window_start)
);
ALTER TABLE credential_usage_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_usage_windows FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS credential_usage_windows_isolation ON credential_usage_windows;
CREATE POLICY credential_usage_windows_isolation ON credential_usage_windows
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON credential_usage_windows TO trstctl_app;

-- misuse_findings is the Enterprise governance misuse-detection read model: one
-- row per detected deviation (one per credential, rule and day), projected from
-- misuse.finding.detected by the licensed projection, which rebuilds it.
CREATE TABLE IF NOT EXISTS misuse_findings (
    tenant_id      uuid        NOT NULL,
    finding_id     text        NOT NULL CHECK (finding_id <> ''),
    rule           text        NOT NULL CHECK (rule IN ('new_source_lease', 'secret_read_burst')),
    credential_id  text        NOT NULL CHECK (credential_id <> ''),
    principal      text        NOT NULL DEFAULT '',
    source         text        NOT NULL DEFAULT '',
    window_start   timestamptz NOT NULL,
    observed_count integer     NOT NULL CHECK (observed_count >= 1),
    baseline       integer     NOT NULL DEFAULT 0 CHECK (baseline >= 0),
    alerted        boolean     NOT NULL,
    detected_at    timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, finding_id)
);
ALTER TABLE misuse_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE misuse_findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS misuse_findings_isolation ON misuse_findings;
CREATE POLICY misuse_findings_isolation ON misuse_findings
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON misuse_findings TO trstctl_app;
