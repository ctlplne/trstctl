-- An MDM SCEP JWS is a single-use enrollment credential. This table is an
-- operational uniqueness fence, like idempotency_keys, not a certificate read
-- model. The audit and issued certificate remain event sourced. A PostgreSQL
-- primary key arbitrates concurrent control planes and survives process restarts.
CREATE TABLE mdm_scep_nonce_fences (
    tenant_id UUID NOT NULL,
    nonce_sha256 CHAR(64) NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, nonce_sha256),
    CHECK (nonce_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE INDEX mdm_scep_nonce_fences_expiry_idx
    ON mdm_scep_nonce_fences (tenant_id, valid_until);

ALTER TABLE mdm_scep_nonce_fences ENABLE ROW LEVEL SECURITY;
ALTER TABLE mdm_scep_nonce_fences FORCE ROW LEVEL SECURITY;
CREATE POLICY mdm_scep_nonce_fences_isolation ON mdm_scep_nonce_fences
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, DELETE ON mdm_scep_nonce_fences TO trstctl_app;
