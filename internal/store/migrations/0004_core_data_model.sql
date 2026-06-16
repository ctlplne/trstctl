-- Core data model (S3.1): the top-level domain entities, all tenant-scoped per
-- AN-1. Every table carries tenant_id, ENABLEs + FORCEs row-level security, and
-- has a USING + WITH CHECK policy keyed on the trstctl.tenant_id GUC (unset => the
-- expression is NULL => no rows visible or writable, fail closed). Application
-- writes happen under RLS via Store.WithTenant. A UNIQUE (tenant_id, id) on the
-- referenced tables lets cross-entity foreign keys be tenant-consistent.

-- owners: who a credential belongs to (User | Team | Workload | Service).
CREATE TABLE owners (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    kind       text NOT NULL,
    name       text NOT NULL,
    email      text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

-- issuers: an X.509 CA (carries a PEM chain) or the chainless SSH CA (a single
-- trusted signing key, no chain). public_key holds the SSH CA's signing key.
CREATE TABLE issuers (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    kind       text NOT NULL,
    name       text NOT NULL,
    chain      text[] NOT NULL DEFAULT '{}',
    public_key text NOT NULL DEFAULT '',
    internal   boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id)
);

-- identities: the abstract credential, discriminated by kind. Stores metadata
-- only; secret/key material lives behind the crypto boundary (AN-3/AN-8), never
-- here. References its owner (required) and issuer (optional), within the tenant.
CREATE TABLE identities (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    kind       text NOT NULL,
    name       text NOT NULL,
    owner_id   uuid NOT NULL,
    issuer_id  uuid,
    status     text NOT NULL DEFAULT 'requested',
    not_before timestamptz,
    not_after  timestamptz,
    attributes jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, owner_id)  REFERENCES owners  (tenant_id, id),
    FOREIGN KEY (tenant_id, issuer_id) REFERENCES issuers (tenant_id, id)
);

-- deployment_targets: where credentials get deployed (connector targets).
CREATE TABLE deployment_targets (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    name       text NOT NULL,
    type       text NOT NULL,
    config     jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);

-- agents: in-network agents.
CREATE TABLE agents (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL,
    name         text NOT NULL,
    status       text NOT NULL DEFAULT 'unknown',
    version      text NOT NULL DEFAULT '',
    last_seen_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- policy_bindings: bind a policy to a scope.
CREATE TABLE policy_bindings (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    name       text NOT NULL,
    policy     text NOT NULL,
    scope      jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);

-- attestations: the evidence chain that justified a credential issuance (F30).
CREATE TABLE attestations (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL,
    identity_id uuid,
    kind        text NOT NULL,
    evidence    jsonb NOT NULL DEFAULT '{}',
    verified_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id)
);

-- AN-1: row-level security on every table; a fail-closed policy keyed on the
-- tenant GUC; grants to the RLS-subject role (superusers/owners bypass, so app
-- traffic runs as trstctl_app under Store.WithTenant).
ALTER TABLE owners             ENABLE ROW LEVEL SECURITY;
ALTER TABLE owners             FORCE  ROW LEVEL SECURITY;
ALTER TABLE issuers            ENABLE ROW LEVEL SECURITY;
ALTER TABLE issuers            FORCE  ROW LEVEL SECURITY;
ALTER TABLE identities         ENABLE ROW LEVEL SECURITY;
ALTER TABLE identities         FORCE  ROW LEVEL SECURITY;
ALTER TABLE deployment_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE deployment_targets FORCE  ROW LEVEL SECURITY;
ALTER TABLE agents             ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents             FORCE  ROW LEVEL SECURITY;
ALTER TABLE policy_bindings    ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_bindings    FORCE  ROW LEVEL SECURITY;
ALTER TABLE attestations       ENABLE ROW LEVEL SECURITY;
ALTER TABLE attestations       FORCE  ROW LEVEL SECURITY;

CREATE POLICY owners_isolation ON owners
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
CREATE POLICY issuers_isolation ON issuers
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
CREATE POLICY identities_isolation ON identities
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
CREATE POLICY deployment_targets_isolation ON deployment_targets
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
CREATE POLICY agents_isolation ON agents
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
CREATE POLICY policy_bindings_isolation ON policy_bindings
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
CREATE POLICY attestations_isolation ON attestations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON owners             TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON issuers            TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON identities         TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON deployment_targets TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON agents             TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON policy_bindings    TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON attestations       TO trstctl_app;
