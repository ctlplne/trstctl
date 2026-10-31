-- A156: an Intune poll schedule can name the Entra app registration whose client
-- secret token_ref holds; the network relay exchanges that secret per attempt for
-- a Microsoft Graph token. Only identifiers are stored here; the secret stays in
-- the tenant secret store.
ALTER TABLE mdm_poll_schedules
    ADD COLUMN IF NOT EXISTS entra_authority text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS entra_directory_tenant_id text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS entra_client_id text NOT NULL DEFAULT '';
