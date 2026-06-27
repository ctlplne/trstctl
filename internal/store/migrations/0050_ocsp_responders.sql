-- Delegated OCSP responders (C4-3): the online OCSP responder must not be the CA
-- certificate/key. This table is the tenant-scoped active-responder projection;
-- rotation history lives in the append-only event log (AN-2).

CREATE TABLE ca_ocsp_responders (
    tenant_id           uuid NOT NULL,
    ca_id               uuid NOT NULL,
    serial              text NOT NULL,
    responder_cert_der  bytea NOT NULL,
    not_before          timestamptz NOT NULL,
    not_after           timestamptz NOT NULL,
    rotated_from_serial text NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, ca_id)
);

ALTER TABLE ca_ocsp_responders ENABLE ROW LEVEL SECURITY;
ALTER TABLE ca_ocsp_responders FORCE ROW LEVEL SECURITY;

CREATE POLICY ca_ocsp_responders_isolation ON ca_ocsp_responders
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX ca_ocsp_responders_expiry_idx ON ca_ocsp_responders (tenant_id, ca_id, not_after);

GRANT SELECT, INSERT, UPDATE, DELETE ON ca_ocsp_responders TO trstctl_app;
