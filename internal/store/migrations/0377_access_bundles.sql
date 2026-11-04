-- A251: agent access bundles. A bundle is a reusable set of permissions for
-- custom agents, CI jobs and private MCP servers, with a ceiling on how long
-- one run's credential may live. A grant gives a bundle to a user or a machine,
-- optionally until a time. A run is a short-lived API token minted under one or
-- more of a principal's grants; its authority is derived again from the live
-- grants at every use, so removing a grant or deleting a bundle takes effect on
-- the next request. Projections of access.bundle.saved, access.bundle.deleted,
-- access.bundle.granted, access.bundle.ungranted, access.bundle.run_issued and
-- access.bundle.run_revoked; access_bundle_activity keeps one metadata row per
-- event (never a credential or a request body).
CREATE TABLE IF NOT EXISTS access_bundles (
    tenant_id           uuid        NOT NULL,
    id                  uuid        NOT NULL,
    name                text        NOT NULL CHECK (length(btrim(name)) > 0 AND length(name) <= 200),
    description         text        NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    permissions         text[]      NOT NULL,
    audiences           text[]      NOT NULL DEFAULT '{}',
    max_run_ttl_seconds integer     NOT NULL CHECK (max_run_ttl_seconds BETWEEN 60 AND 86400),
    revision            bigint      NOT NULL CHECK (revision > 0),
    created_by          text        NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL,
    updated_at          timestamptz NOT NULL,
    deleted_at          timestamptz,
    deleted_by          text        NOT NULL DEFAULT '',
    event_sequence      bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id)
);
-- The API refuses a second live bundle with a name; the index only serves
-- lookups, so a projection never fails on a name. A deleted bundle's name may
-- be used again, by a new bundle its old grants and runs never reach.
CREATE INDEX IF NOT EXISTS access_bundles_live_name_idx ON access_bundles (tenant_id, lower(name)) WHERE deleted_at IS NULL;
CREATE TABLE IF NOT EXISTS access_bundle_grants (
    tenant_id      uuid        NOT NULL,
    id             uuid        NOT NULL,
    bundle_id      uuid        NOT NULL,
    principal_type text        NOT NULL CHECK (principal_type IN ('user', 'machine')),
    principal      text        NOT NULL CHECK (length(btrim(principal)) > 0 AND length(principal) <= 320),
    expires_at     timestamptz,
    granted_by     text        NOT NULL DEFAULT '',
    granted_at     timestamptz NOT NULL,
    removed_at     timestamptz,
    removed_by     text        NOT NULL DEFAULT '',
    removed_reason text        NOT NULL DEFAULT '',
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, bundle_id) REFERENCES access_bundles (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS access_bundle_grants_principal_idx ON access_bundle_grants (tenant_id, principal) WHERE removed_at IS NULL;
CREATE INDEX IF NOT EXISTS access_bundle_grants_bundle_idx ON access_bundle_grants (tenant_id, bundle_id);
CREATE TABLE IF NOT EXISTS access_bundle_runs (
    tenant_id      uuid        NOT NULL,
    id             uuid        NOT NULL,
    principal      text        NOT NULL,
    bundle_ids     uuid[]      NOT NULL,
    grant_ids      uuid[]      NOT NULL,
    permissions    text[]      NOT NULL,
    label          text        NOT NULL DEFAULT '' CHECK (length(label) <= 120),
    expires_at     timestamptz NOT NULL,
    issued_by      text        NOT NULL DEFAULT '',
    issued_at      timestamptz NOT NULL,
    revoked_at     timestamptz,
    revoked_by     text        NOT NULL DEFAULT '',
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS access_bundle_runs_principal_idx ON access_bundle_runs (tenant_id, principal, issued_at DESC);
CREATE TABLE IF NOT EXISTS access_bundle_activity (
    tenant_id      uuid        NOT NULL,
    event_id       text        NOT NULL CHECK (event_id <> ''),
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    at             timestamptz NOT NULL,
    action         text        NOT NULL CHECK (action IN ('saved', 'deleted', 'granted', 'ungranted', 'run_issued', 'run_revoked')),
    bundle_ids     uuid[]      NOT NULL DEFAULT '{}',
    bundle_names   text[]      NOT NULL DEFAULT '{}',
    grant_id       uuid,
    run_id         uuid,
    principal      text        NOT NULL DEFAULT '',
    actor          text        NOT NULL DEFAULT '',
    detail         text        NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX IF NOT EXISTS access_bundle_activity_at_idx ON access_bundle_activity (tenant_id, at DESC, event_sequence DESC);
ALTER TABLE access_bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_bundles FORCE ROW LEVEL SECURITY;
ALTER TABLE access_bundle_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_bundle_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE access_bundle_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_bundle_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE access_bundle_activity ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_bundle_activity FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS access_bundles_isolation ON access_bundles;
CREATE POLICY access_bundles_isolation ON access_bundles
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
DROP POLICY IF EXISTS access_bundle_grants_isolation ON access_bundle_grants;
CREATE POLICY access_bundle_grants_isolation ON access_bundle_grants
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
DROP POLICY IF EXISTS access_bundle_runs_isolation ON access_bundle_runs;
CREATE POLICY access_bundle_runs_isolation ON access_bundle_runs
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
DROP POLICY IF EXISTS access_bundle_activity_isolation ON access_bundle_activity;
CREATE POLICY access_bundle_activity_isolation ON access_bundle_activity
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON access_bundles, access_bundle_grants, access_bundle_runs, access_bundle_activity TO trstctl_app;
