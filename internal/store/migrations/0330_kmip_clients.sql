-- Tenant self-service KMIP clients.
--
-- A tenant registers the KMIP clients it trusts. A registration starts with a
-- one-time enrollment secret; the client's first KMIP request presents its TLS
-- certificate (the handshake proves it holds the key) and the secret as KMIP
-- username and password, which binds that certificate to the registration.
-- From then on the certificate alone selects the tenant on the shared KMIP
-- listener. Binding needs both, so no tenant can claim another tenant's
-- client by registering a certificate it has only seen. A certificate is bound
-- to at most one registration across all tenants.
--
-- A pure read-model projection of kmip.client.* events. The enrollment secret
-- is stored only as the SHA-256 of a high-entropy value; who registered the
-- client stays in the event, where subject erasure reaches it.
CREATE TABLE IF NOT EXISTS kmip_clients (
    tenant_id             uuid        NOT NULL,
    id                    uuid        NOT NULL,
    name                  text        NOT NULL,
    enrollment_hash       text        NOT NULL DEFAULT '',
    enrollment_expires_at timestamptz,
    fingerprint           text,
    subject               text        NOT NULL DEFAULT '',
    not_after             timestamptz,
    enrolled_at           timestamptz,
    created_at            timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT kmip_clients_name_chk CHECK (length(name) BETWEEN 1 AND 128)
);

-- The listener resolves a certificate, and an enrollment names a registration,
-- before any tenant is known: both lookups are global.
CREATE UNIQUE INDEX IF NOT EXISTS kmip_clients_fingerprint ON kmip_clients (fingerprint) WHERE fingerprint IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS kmip_clients_id ON kmip_clients (id);

ALTER TABLE kmip_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE kmip_clients FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS kmip_clients_isolation ON kmip_clients;
CREATE POLICY kmip_clients_isolation ON kmip_clients
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON kmip_clients TO trstctl_app;
