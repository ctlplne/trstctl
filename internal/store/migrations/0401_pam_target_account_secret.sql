-- A261: a vaulted PAM target. A database target may name the application
-- secret that holds one account's current credential (an A240 static
-- rotation keeps it current): its sessions are delivered through the
-- target's gateway signed in as that account, with no per-session lease. A
-- target registered before names none and leases as it did.
ALTER TABLE pam_targets ADD COLUMN IF NOT EXISTS account_secret text NOT NULL DEFAULT '';
