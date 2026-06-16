-- Private/enterprise CA hierarchy & key ceremonies (F48, sprint S4.15): the
-- entities for operating trstctl as its own CA — the CA hierarchy and its
-- certificates, and the m-of-n key-generation ceremonies that gate CA-key
-- creation. This extends S3.1 (it does not change the issuers table). Per AN-1
-- every row carries tenant_id and is confined by row-level security.

-- ca_authorities is the CA hierarchy: each root or intermediate trstctl operates,
-- with its certificate (public material; the signing key is custodied by the
-- signer/HSM, AN-4) and its policy (name/path-length/EKU constraints). replaces_id
-- links a rotated CA to its predecessor.
CREATE TABLE ca_authorities (
    id                  uuid PRIMARY KEY,
    tenant_id           uuid NOT NULL,
    parent_id           uuid,
    common_name         text NOT NULL,
    kind                text NOT NULL,                 -- 'root' | 'intermediate'
    status              text NOT NULL DEFAULT 'active', -- 'active' | 'superseded' | 'revoked'
    certificate_pem     text NOT NULL,                 -- CA cert + chain, PEM
    serial              text NOT NULL DEFAULT '',
    not_after           timestamptz,
    max_path_len        integer NOT NULL DEFAULT -1,
    permitted_dns_names text[] NOT NULL DEFAULT '{}',
    ekus                text[] NOT NULL DEFAULT '{}',
    replaces_id         uuid,
    created_at          timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (parent_id) REFERENCES ca_authorities (id) ON DELETE SET NULL,
    FOREIGN KEY (replaces_id) REFERENCES ca_authorities (id) ON DELETE SET NULL
);

ALTER TABLE ca_authorities ENABLE ROW LEVEL SECURITY;
ALTER TABLE ca_authorities FORCE ROW LEVEL SECURITY;

CREATE POLICY ca_authorities_isolation ON ca_authorities
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX ca_authorities_tenant_idx ON ca_authorities (tenant_id, status);

GRANT SELECT, INSERT, UPDATE, DELETE ON ca_authorities TO trstctl_app;

-- ca_key_ceremonies records an m-of-n key-generation ceremony: the CA key is
-- created only once `threshold` distinct custodians have approved.
CREATE TABLE ca_key_ceremonies (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL,
    purpose      text NOT NULL,
    threshold    integer NOT NULL,
    status       text NOT NULL DEFAULT 'pending', -- 'pending' | 'completed'
    created_at   timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

ALTER TABLE ca_key_ceremonies ENABLE ROW LEVEL SECURITY;
ALTER TABLE ca_key_ceremonies FORCE ROW LEVEL SECURITY;

CREATE POLICY ca_key_ceremonies_isolation ON ca_key_ceremonies
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON ca_key_ceremonies TO trstctl_app;

-- ca_ceremony_approvals records each custodian's approval of a ceremony. The
-- primary key makes a custodian's approval idempotent.
CREATE TABLE ca_ceremony_approvals (
    tenant_id   uuid NOT NULL,
    ceremony_id uuid NOT NULL,
    custodian   text NOT NULL,
    approved_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, ceremony_id, custodian),
    FOREIGN KEY (ceremony_id) REFERENCES ca_key_ceremonies (id) ON DELETE CASCADE
);

ALTER TABLE ca_ceremony_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE ca_ceremony_approvals FORCE ROW LEVEL SECURITY;

CREATE POLICY ca_ceremony_approvals_isolation ON ca_ceremony_approvals
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON ca_ceremony_approvals TO trstctl_app;
