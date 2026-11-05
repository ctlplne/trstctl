-- A260 part 2: privileged accounts imported from discovery. An import names
-- the staged accounts, the folder they go into and optionally the access
-- template that will govern them; it is applied only after independent
-- review (the operation approval it consumes) and grants nothing by itself:
-- no target, role binding, session or credential changes. Projected from
-- pam.discovery.imported; one row per imported account, as the import saw it.
CREATE TABLE IF NOT EXISTS pam_imported_accounts (
    tenant_id uuid NOT NULL,
    provider_id text NOT NULL,
    account_key text NOT NULL,
    discovered_account_id uuid NOT NULL,
    name text NOT NULL,
    kind text NOT NULL,
    privileges jsonb NOT NULL,
    folder text NOT NULL,
    template_id uuid,
    reason text NOT NULL,
    import_request_id uuid NOT NULL,
    approval_request_id uuid NOT NULL,
    imported_by text NOT NULL,
    imported_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, provider_id, account_key)
);
CREATE INDEX IF NOT EXISTS pam_imported_accounts_folder_idx ON pam_imported_accounts (tenant_id, folder);
ALTER TABLE pam_imported_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_imported_accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_imported_accounts_isolation ON pam_imported_accounts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_imported_accounts TO trstctl_app;

-- Why a staged account was dismissed (pam.discovery.dismissed); a later scan
-- that finds it changed stages it again.
ALTER TABLE pam_discovered_accounts ADD COLUMN IF NOT EXISTS dismissed_reason text NOT NULL DEFAULT '';
ALTER TABLE pam_discovered_accounts ADD COLUMN IF NOT EXISTS dismissed_by text NOT NULL DEFAULT '';
