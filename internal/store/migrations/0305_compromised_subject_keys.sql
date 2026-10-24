-- SPDX-License-Identifier: BUSL-1.1
-- Owner finding on B11-8: issuance refused a compromised subject key by reading
-- and parsing every keyCompromise-revoked certificate of the tenant, and above
-- 10,000 it refused all issuance in the tenant. The subject key of each
-- certificate revoked for keyCompromise is now recorded once, by the
-- revocation projection (backfilled at startup for older revocations), and
-- issuance makes one indexed lookup by tenant and SPKI SHA-256.
CREATE TABLE IF NOT EXISTS compromised_subject_keys (
    tenant_id               uuid        NOT NULL,
    certificate_fingerprint text        NOT NULL,
    spki_sha256             text        NOT NULL CHECK (spki_sha256 ~ '^[0-9a-f]{64}$'),
    revoked_at              timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, certificate_fingerprint)
);
CREATE INDEX IF NOT EXISTS compromised_subject_keys_spki_idx
    ON compromised_subject_keys (tenant_id, spki_sha256);
ALTER TABLE compromised_subject_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE compromised_subject_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS compromised_subject_keys_isolation ON compromised_subject_keys;
CREATE POLICY compromised_subject_keys_isolation ON compromised_subject_keys
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON compromised_subject_keys TO trstctl_app;
