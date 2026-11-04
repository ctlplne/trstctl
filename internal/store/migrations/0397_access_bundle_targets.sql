-- A257: an access bundle names the accounts its runs may open privileged
-- sessions to: each a PAM target (type and ID) with the roles allowed on it.
-- A bundle saved before names none, so its runs open none.
ALTER TABLE access_bundles
    ADD COLUMN IF NOT EXISTS access_targets jsonb NOT NULL DEFAULT '[]'::jsonb;
