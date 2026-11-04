-- N2: disabling a certificate version in Azure Key Vault. Key Vault cannot
-- revoke a certificate; disabling a version stops the vault serving it to the
-- applications that read it there, while the certificate stays valid until it
-- expires or its issuing CA revokes it. Projections of
-- certificate.key_vault_disable_requested and certificate.key_vault_disabled;
-- a request not disabled yet reads its outbox job's state.
CREATE TABLE IF NOT EXISTS certificate_key_vault_disables (
    tenant_id         uuid        NOT NULL,
    id                uuid        NOT NULL,
    certificate_id    uuid        NOT NULL,
    resource_id       text        NOT NULL,
    source_id         uuid        NOT NULL,
    reason            text        NOT NULL DEFAULT '',
    requested_by      text        NOT NULL,
    requested_at      timestamptz NOT NULL,
    disabled          boolean     NOT NULL DEFAULT false,
    disabled_at       timestamptz,
    vault_updated_at  timestamptz,
    event_sequence    bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS certificate_key_vault_disables_certificate_idx
    ON certificate_key_vault_disables (tenant_id, certificate_id, requested_at DESC);
ALTER TABLE certificate_key_vault_disables ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificate_key_vault_disables FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certificate_key_vault_disables_isolation ON certificate_key_vault_disables;
CREATE POLICY certificate_key_vault_disables_isolation ON certificate_key_vault_disables
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON certificate_key_vault_disables TO trstctl_app;
