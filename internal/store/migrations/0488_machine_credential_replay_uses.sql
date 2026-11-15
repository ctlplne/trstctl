-- M4-L4: a machine-login method may let one subject token make several token
-- exchanges before it expires (exchange_uses). Each single-use record counts
-- the uses its token made; a record from before counts one, the use that
-- created it, so every earlier token keeps the single use it had.
ALTER TABLE machine_credential_replays
    ADD COLUMN IF NOT EXISTS uses integer NOT NULL DEFAULT 1;
