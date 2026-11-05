-- A261 part 3: account folders. A folder names the access template every
-- account in it takes: a session request or check-out for a target in the
-- folder carries the template's reason, approvals and longest length, and a
-- request naming another template is refused. Projected from pam.folder.saved
-- and pam.folder.deleted.
CREATE TABLE IF NOT EXISTS pam_folders (
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    template_id text NOT NULL,
    description text NOT NULL,
    revision bigint NOT NULL,
    saved_by text NOT NULL,
    saved_at timestamptz NOT NULL,
    deleted_at timestamptz,
    PRIMARY KEY (tenant_id, name)
);
ALTER TABLE pam_folders ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_folders FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_folders_isolation ON pam_folders
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_folders TO trstctl_app;

-- A registered PAM target names the folder it belongs to ('' for none), and a
-- template may require that sessions through it are recorded. Existing rows
-- keep their meaning: no folder, recording not required.
ALTER TABLE pam_targets ADD COLUMN IF NOT EXISTS folder text NOT NULL DEFAULT '';
ALTER TABLE pam_access_templates ADD COLUMN IF NOT EXISTS require_recording boolean NOT NULL DEFAULT false;
