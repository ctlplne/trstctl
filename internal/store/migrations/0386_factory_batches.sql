-- P12: factory provisioning. A factory batch is a quota of device birth
-- certificates a station issues offline under one edge delegation; the
-- station's journal reconciles each birth certificate here, those past the
-- quota recorded as over-production. A device enrolls once with its birth
-- certificate (first boot) and renews with its operational certificate.
-- Projections of edge.factory_batch.created, edge.factory_birth.recorded and
-- edge.factory_device.enrolled.
CREATE TABLE IF NOT EXISTS factory_batches (
    tenant_id           uuid        NOT NULL,
    id                  uuid        NOT NULL,
    delegation_id       text        NOT NULL,
    label               text        NOT NULL,
    quota               integer     NOT NULL CHECK (quota > 0),
    birth_ttl_seconds   integer     NOT NULL CHECK (birth_ttl_seconds > 0),
    operational_profile text        NOT NULL DEFAULT '',
    created_by          text        NOT NULL,
    created_at          timestamptz NOT NULL,
    recorded            integer     NOT NULL DEFAULT 0,
    over_quota          integer     NOT NULL DEFAULT 0,
    event_sequence      bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id)
);
CREATE TABLE IF NOT EXISTS factory_birth_certificates (
    tenant_id               uuid        NOT NULL,
    batch_id                uuid        NOT NULL,
    serial                  text        NOT NULL,
    device_name             text        NOT NULL,
    fingerprint             text        NOT NULL,
    certificate_der         bytea       NOT NULL,
    not_after               timestamptz NOT NULL,
    over_quota              boolean     NOT NULL DEFAULT false,
    recorded_at             timestamptz NOT NULL,
    enrolled                boolean     NOT NULL DEFAULT false,
    enrolled_at             timestamptz,
    csr_sha256              text        NOT NULL DEFAULT '',
    operational_serial      text        NOT NULL DEFAULT '',
    operational_fingerprint text        NOT NULL DEFAULT '',
    operational_der         bytea,
    renewals                integer     NOT NULL DEFAULT 0,
    event_sequence          bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, batch_id, serial)
);
CREATE UNIQUE INDEX IF NOT EXISTS factory_birth_certificates_fingerprint_idx ON factory_birth_certificates (tenant_id, fingerprint);
CREATE INDEX IF NOT EXISTS factory_birth_certificates_operational_idx ON factory_birth_certificates (tenant_id, operational_fingerprint);
ALTER TABLE factory_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE factory_batches FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS factory_batches_isolation ON factory_batches;
CREATE POLICY factory_batches_isolation ON factory_batches
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
ALTER TABLE factory_birth_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE factory_birth_certificates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS factory_birth_certificates_isolation ON factory_birth_certificates;
CREATE POLICY factory_birth_certificates_isolation ON factory_birth_certificates
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON factory_batches TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON factory_birth_certificates TO trstctl_app;
