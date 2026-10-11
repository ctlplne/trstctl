-- Public CA cross-certificates are recovered from the immutable result event.
-- One ceremony produces one receipt; projection and ceremony completion share
-- the same tenant transaction so a restart cannot expose half a result.
CREATE TABLE ca_cross_sign_receipts (
    tenant_id UUID NOT NULL,
    ceremony_id UUID NOT NULL,
    issuer_authority_id UUID NOT NULL,
    target_sha256 CHAR(64) NOT NULL,
    target_certificate_der BYTEA NOT NULL,
    cross_certificate_der BYTEA NOT NULL,
    imported BOOLEAN NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, ceremony_id),
    CHECK (target_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (octet_length(target_certificate_der) > 0),
    CHECK (octet_length(cross_certificate_der) > 0)
);

CREATE INDEX ca_cross_sign_receipts_issuer_idx
    ON ca_cross_sign_receipts (tenant_id, issuer_authority_id, completed_at DESC);

ALTER TABLE ca_cross_sign_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ca_cross_sign_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY ca_cross_sign_receipts_isolation ON ca_cross_sign_receipts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON ca_cross_sign_receipts TO trstctl_app;
