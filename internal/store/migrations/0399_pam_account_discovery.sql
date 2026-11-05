-- A260: privileged account discovery.
--
-- A discovery source is one of the tenant's dynamic-secret providers whose
-- administrator connection reads its target's accounts (PostgreSQL, MySQL,
-- SQL Server, a Linux or Unix host), scanned on demand or every interval.
-- Projected from pam.discovery.source_saved and pam.discovery.source_deleted.
CREATE TABLE IF NOT EXISTS pam_discovery_sources (
    tenant_id uuid NOT NULL,
    provider_id text NOT NULL,
    provider_type text NOT NULL,
    interval_seconds integer NOT NULL CHECK (interval_seconds = 0 OR interval_seconds >= 3600),
    saved_by text NOT NULL,
    saved_at timestamptz NOT NULL,
    deleted_at timestamptz,
    PRIMARY KEY (tenant_id, provider_id)
);
ALTER TABLE pam_discovery_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_discovery_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_discovery_sources_isolation ON pam_discovery_sources
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_discovery_sources TO trstctl_app;

-- One scan of a source, projected from pam.discovery.run_completed: what it
-- found and how that differs from the source's previous complete scan. A
-- failed scan records why and changes no account.
CREATE TABLE IF NOT EXISTS pam_discovery_runs (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    provider_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('completed', 'failed')),
    failure text NOT NULL DEFAULT '',
    started_at timestamptz NOT NULL,
    finished_at timestamptz NOT NULL,
    requested_by text NOT NULL,
    accounts integer NOT NULL DEFAULT 0,
    added integer NOT NULL DEFAULT 0,
    removed integer NOT NULL DEFAULT 0,
    changed integer NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS pam_discovery_runs_source_idx ON pam_discovery_runs (tenant_id, provider_id, finished_at DESC);
ALTER TABLE pam_discovery_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_discovery_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_discovery_runs_isolation ON pam_discovery_runs
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_discovery_runs TO trstctl_app;

-- The changes one scan found: an account added, removed or changed since the
-- source's previous complete scan, as the scan saw it (as the previous scan
-- saw it, for a removal).
CREATE TABLE IF NOT EXISTS pam_discovery_run_changes (
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    account_key text NOT NULL,
    change text NOT NULL CHECK (change IN ('added', 'removed', 'changed')),
    account jsonb NOT NULL,
    PRIMARY KEY (tenant_id, run_id, account_key)
);
ALTER TABLE pam_discovery_run_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_discovery_run_changes FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_discovery_run_changes_isolation ON pam_discovery_run_changes
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_discovery_run_changes TO trstctl_app;

-- The privileged accounts discovery has staged, one row per source and
-- account: as last seen, when first and last seen, and the scan that found
-- it gone (removed_run). Status is staged until it is imported (part 2) or
-- dismissed; importing never grants access by itself.
CREATE TABLE IF NOT EXISTS pam_discovered_accounts (
    tenant_id uuid NOT NULL,
    provider_id text NOT NULL,
    account_key text NOT NULL,
    id uuid NOT NULL,
    name text NOT NULL,
    kind text NOT NULL,
    privileges jsonb NOT NULL,
    disabled boolean NOT NULL DEFAULT false,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_seen_run uuid NOT NULL,
    first_seen_at timestamptz NOT NULL,
    last_seen_run uuid NOT NULL,
    last_seen_at timestamptz NOT NULL,
    changed_run uuid,
    removed_run uuid,
    removed_at timestamptz,
    status text NOT NULL DEFAULT 'staged' CHECK (status IN ('staged', 'imported', 'dismissed')),
    PRIMARY KEY (tenant_id, provider_id, account_key)
);
CREATE INDEX IF NOT EXISTS pam_discovered_accounts_id_idx ON pam_discovered_accounts (tenant_id, id);
ALTER TABLE pam_discovered_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_discovered_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_discovered_accounts_isolation ON pam_discovered_accounts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_discovered_accounts TO trstctl_app;
