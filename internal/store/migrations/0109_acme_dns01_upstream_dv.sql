-- Opt-in: this provider config may be used for UPSTREAM domain validation
-- (epic B7).
--
-- The configs already here were created for one purpose: letting trstctl's own
-- ACME responder verify a challenge a client published. Using them for the
-- other direction — publishing a record so a PUBLIC CA validates a domain for
-- us — is a materially different act with the same credentials. It writes to
-- the operator's real DNS zone on a schedule nobody triggered, on behalf of an
-- authority outside this system.
--
-- So it defaults to false, and an operator turns it on per config. An operator
-- who configured Route 53 credentials so their ACME clients could validate has
-- not thereby agreed that trstctl may publish records into that zone whenever a
-- public CA asks. Defaulting to true would silently widen the blast radius of a
-- credential they already gave us for something narrower.
--
-- online-safe: ADD COLUMN with a constant default is catalog-only in
-- PostgreSQL 11+. RLS and FORCE are inherited from 0063.
ALTER TABLE acme_dns01_provider_configs
    ADD COLUMN IF NOT EXISTS allow_upstream_dv boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN acme_dns01_provider_configs.allow_upstream_dv IS
    'Whether this provider config may publish challenge records for UPSTREAM domain validation against an external CA (epic B7). Defaults false: credentials given so trstctl could verify a challenge are not thereby consent to publish into the zone on an external authority''s behalf.';
