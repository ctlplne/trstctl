-- A154: an hmac-dynamic MDM SCEP policy names the tenant secret that holds the
-- username:password an MDM uses to fetch per-device challenges. Only the
-- secret:// reference is stored here; the value stays sealed in the tenant
-- secret store.
ALTER TABLE mdm_scep_policies
    ADD COLUMN IF NOT EXISTS challenge_credential_ref text NOT NULL DEFAULT '';
