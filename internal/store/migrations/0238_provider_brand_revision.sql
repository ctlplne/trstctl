-- A Provider brand edit must be based on the exact projected version the
-- operator reviewed. Historical rows start at revision 0; every new authority
-- event replaces it with its immutable event ID during projection/replay.
ALTER TABLE tenant_branding ADD COLUMN IF NOT EXISTS revision text NOT NULL DEFAULT '0';
