-- A235: the secrets workspace. A project (an application) has environments;
-- a secret belongs to one by its name, "<project>/<environment>/<folder…>/<key>",
-- so it stays one row in the one native store. A restricted environment's
-- secrets are readable and writable only by the project's members granted that
-- environment; an unrestricted one behaves as tenant-level secrets do. Projections
-- of secret.project.created, secret.project.environment_added,
-- secret.project.member_granted and secret.project.member_revoked.
CREATE TABLE IF NOT EXISTS secret_projects (
    tenant_id      uuid        NOT NULL,
    slug           text        NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name           text        NOT NULL DEFAULT '',
    owner_id       text        NOT NULL DEFAULT '',
    created_by     text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, slug)
);
CREATE TABLE IF NOT EXISTS secret_project_environments (
    tenant_id      uuid        NOT NULL,
    project        text        NOT NULL,
    slug           text        NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name           text        NOT NULL DEFAULT '',
    restricted     boolean     NOT NULL DEFAULT false,
    position       integer     NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, project, slug)
);
CREATE TABLE IF NOT EXISTS secret_project_members (
    tenant_id      uuid        NOT NULL,
    project        text        NOT NULL,
    subject        text        NOT NULL CHECK (subject <> ''),
    role           text        NOT NULL CHECK (role IN ('viewer', 'developer', 'admin')),
    environments   text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(environments) <= 64),
    granted_by     text        NOT NULL DEFAULT '',
    granted_at     timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, project, subject)
);
ALTER TABLE secret_projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_projects FORCE ROW LEVEL SECURITY;
ALTER TABLE secret_project_environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_project_environments FORCE ROW LEVEL SECURITY;
ALTER TABLE secret_project_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_project_members FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS secret_projects_isolation ON secret_projects;
CREATE POLICY secret_projects_isolation ON secret_projects
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
DROP POLICY IF EXISTS secret_project_environments_isolation ON secret_project_environments;
CREATE POLICY secret_project_environments_isolation ON secret_project_environments
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
DROP POLICY IF EXISTS secret_project_members_isolation ON secret_project_members;
CREATE POLICY secret_project_members_isolation ON secret_project_members
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON secret_projects, secret_project_environments, secret_project_members TO trstctl_app;
