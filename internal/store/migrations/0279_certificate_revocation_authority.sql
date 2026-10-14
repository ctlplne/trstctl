-- A revocation command is an independent denial before its event enters the
-- broker. Its exact payload survives an append or projection crash.
CREATE TABLE certificate_revocation_authority_commands (
    tenant_id uuid NOT NULL,
    event_id text NOT NULL CHECK (event_id <> ''),
    event_type text NOT NULL CHECK (event_type IN ('certificate.revocation.batch.applied', 'certificate.revoked')),
    event_time timestamptz NOT NULL,
    event_schema_version integer NOT NULL CHECK (event_schema_version > 0),
    event_payload bytea,
    payload_sha256 char(64),
    request_binding char(64) NOT NULL CHECK (request_binding ~ '^[0-9a-f]{64}$'),
    status text NOT NULL DEFAULT 'pending',
    projected_sequence bigint,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, event_id),
    CHECK ((status='pending' AND event_payload IS NOT NULL AND
            payload_sha256 ~ '^[0-9a-f]{64}$' AND projected_sequence IS NULL) OR
           (status='completed' AND event_payload IS NULL AND
            payload_sha256 IS NULL AND projected_sequence > 0))
);
CREATE INDEX certificate_revocation_authority_pending
    ON certificate_revocation_authority_commands (tenant_id, event_id) WHERE status='pending';
ALTER TABLE certificate_revocation_authority_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificate_revocation_authority_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY certificate_revocation_authority_commands_isolation ON certificate_revocation_authority_commands
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON certificate_revocation_authority_commands TO trstctl_app;

-- OCSP and CRL admission use this bounded key, never a scan of the event log.
CREATE TABLE certificate_revocation_authority_fences (
    tenant_id uuid NOT NULL,
    ca_id uuid NOT NULL,
    serial text NOT NULL CHECK (serial <> ''),
    fingerprint char(64) NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    event_id text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed')),
    projected_sequence bigint,
    PRIMARY KEY (tenant_id, ca_id, serial),
    FOREIGN KEY (tenant_id,event_id) REFERENCES certificate_revocation_authority_commands(tenant_id,event_id),
    CHECK ((status='pending' AND projected_sequence IS NULL) OR
           (status='completed' AND projected_sequence > 0))
);
CREATE INDEX certificate_revocation_authority_fences_pending_ca
    ON certificate_revocation_authority_fences (tenant_id,ca_id,serial) WHERE status='pending';
CREATE INDEX certificate_revocation_authority_fences_pending_fingerprint
    ON certificate_revocation_authority_fences (tenant_id,fingerprint) WHERE status='pending';
ALTER TABLE certificate_revocation_authority_fences ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificate_revocation_authority_fences FORCE ROW LEVEL SECURITY;
CREATE POLICY certificate_revocation_authority_fences_isolation ON certificate_revocation_authority_fences
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON certificate_revocation_authority_fences TO trstctl_app;
