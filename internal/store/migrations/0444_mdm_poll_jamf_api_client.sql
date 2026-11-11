-- A156-L1: a Jamf poll schedule can name the Jamf Pro API client whose client
-- secret token_ref holds; the network relay exchanges that secret per attempt at
-- the same Jamf Pro server for an access token. Only the client ID is stored
-- here; the secret stays in the tenant secret store. Online-safe: adding a
-- column with a constant default rewrites no rows.
ALTER TABLE mdm_poll_schedules
    ADD COLUMN IF NOT EXISTS jamf_client_id text NOT NULL DEFAULT '';
