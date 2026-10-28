-- Dynamic-lease rotation commands (A201).
--
-- A dynamic-lease rotation is a rotation command whose provider is
-- dynamic-lease:<provider>. Its worker issues a new lease of the requested
-- lifetime through the durable lease lifecycle, publishes the lease's
-- credential as the next secret version, verifies it and revokes the
-- predecessor lease. ttl_seconds is the requested lifetime (0 for a static
-- rotation) and new_expires_at the issued lease's expiry; both are projected
-- from the command's events like every other column.

ALTER TABLE secret_static_rotation_commands
    ADD COLUMN IF NOT EXISTS ttl_seconds integer NOT NULL DEFAULT 0 CHECK (ttl_seconds >= 0),
    ADD COLUMN IF NOT EXISTS new_expires_at timestamptz;
