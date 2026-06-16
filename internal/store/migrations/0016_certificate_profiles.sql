-- Certificate profiles (S8.1, F53): the versioned, fine-grained rules that govern
-- issuance — allowed key types/sizes, EKUs, name constraints, validity ceilings,
-- and which enrollment protocols may use a profile. Every issuance path validates
-- against its bound profile before signing.
--
-- Versioning: each edit is a NEW row (a new version); prior versions remain
-- resolvable. At most one version per name is `active` at a time (the one new
-- issuance binds to). Per AN-1 every row carries a tenant_id and is confined by
-- row-level security.
CREATE TABLE certificate_profiles (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    name       text NOT NULL,
    version    integer NOT NULL,
    spec       jsonb NOT NULL,            -- the serialized profile.CertificateProfile
    active     boolean NOT NULL DEFAULT true,
    created_by text NOT NULL DEFAULT '',  -- the actor who created this version (audit)
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name, version)
);

-- One active version per (tenant, name): the version new issuance binds to.
CREATE UNIQUE INDEX certificate_profiles_one_active
    ON certificate_profiles (tenant_id, name)
    WHERE active;

ALTER TABLE certificate_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificate_profiles FORCE ROW LEVEL SECURITY;

-- Fail closed: with the tenant GUC unset the predicate is NULL and no rows match.
CREATE POLICY certificate_profiles_isolation ON certificate_profiles
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON certificate_profiles TO trstctl_app;
