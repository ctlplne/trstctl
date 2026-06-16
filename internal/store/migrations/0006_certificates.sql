-- Certificate inventory (F1): the catalog of every known certificate and its
-- metadata, the backbone discovery/lifecycle builds on. Per AN-1 each row carries
-- tenant_id and is confined by row-level security. A certificate is inventoried
-- once per tenant (UNIQUE on its fingerprint); re-ingesting refreshes its row.
CREATE TABLE certificates (
    id                  uuid PRIMARY KEY,
    tenant_id           uuid NOT NULL,
    owner_id            uuid,
    subject             text NOT NULL,
    sans                text[] NOT NULL DEFAULT '{}',
    issuer              text NOT NULL DEFAULT '',
    serial              text NOT NULL DEFAULT '',
    fingerprint         text NOT NULL,
    key_algorithm       text NOT NULL DEFAULT '',
    not_before          timestamptz,
    not_after           timestamptz,
    deployment_location text NOT NULL DEFAULT '',
    source              text NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, fingerprint),
    FOREIGN KEY (tenant_id, owner_id) REFERENCES owners (tenant_id, id)
);

ALTER TABLE certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificates FORCE ROW LEVEL SECURITY;

CREATE POLICY certificates_isolation ON certificates
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- Expiry queries ("what expires before T") are a primary inventory access path.
CREATE INDEX certificates_expiry_idx ON certificates (tenant_id, not_after);

GRANT SELECT, INSERT, UPDATE, DELETE ON certificates TO trstctl_app;
