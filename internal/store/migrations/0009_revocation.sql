-- X.509 revocation infrastructure (F47, sprint S4.16): the revocation status of
-- certificates trstctl issues from its own private CA (F48), serving the OCSP
-- responder and CRL generation. Per AN-1 every row carries tenant_id under RLS.

-- ca_issued_certs records each certificate the internal CA issued, by serial,
-- and its revocation status. A row's presence lets OCSP answer good vs. unknown;
-- a non-null revoked_at marks it revoked (for OCSP and the CRL).
CREATE TABLE ca_issued_certs (
    tenant_id   uuid NOT NULL,
    ca_id       uuid NOT NULL,
    serial      text NOT NULL,
    issued_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz,
    reason_code integer NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, ca_id, serial)
);

ALTER TABLE ca_issued_certs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ca_issued_certs FORCE ROW LEVEL SECURITY;

CREATE POLICY ca_issued_certs_isolation ON ca_issued_certs
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- The CRL scan ("revoked certs for this CA") is the primary list access path.
CREATE INDEX ca_issued_certs_revoked_idx ON ca_issued_certs (tenant_id, ca_id, revoked_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON ca_issued_certs TO trstctl_app;

-- ca_crls holds the CRLs trstctl has generated and published per CA; the latest
-- is the one with the highest crl_number.
CREATE TABLE ca_crls (
    tenant_id   uuid NOT NULL,
    ca_id       uuid NOT NULL,
    crl_number  bigint NOT NULL,
    crl_der     bytea NOT NULL,
    this_update timestamptz NOT NULL,
    next_update timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, ca_id, crl_number)
);

ALTER TABLE ca_crls ENABLE ROW LEVEL SECURITY;
ALTER TABLE ca_crls FORCE ROW LEVEL SECURITY;

CREATE POLICY ca_crls_isolation ON ca_crls
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON ca_crls TO trstctl_app;
