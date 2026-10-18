-- A signer handle is process-wide, even when CA authority read models are RLS
-- isolated. Reserve each handle once before a tenant appends CA authority state.
-- The fixed partition holds only a digest of the opaque handle. On customer
-- offboard its ownership is erased but the digest remains a denial tombstone;
-- an orphaned signer key must never become another tenant's key.
ALTER TABLE tenants ADD CONSTRAINT tenants_ca_signer_claim_partition_reserved_chk
    CHECK (tenant_id <> '00000000-0000-0000-0000-000000000003'::uuid) NOT VALID;
ALTER TABLE tenants VALIDATE CONSTRAINT tenants_ca_signer_claim_partition_reserved_chk;

CREATE TABLE ca_signer_handle_claims (
    tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000003',
    handle_sha256 char(64) NOT NULL,
    owner_tenant_id uuid,
    owner_ceremony_id uuid,
    state text NOT NULL DEFAULT 'claimed',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, handle_sha256),
    CONSTRAINT ca_signer_handle_claims_partition_chk
        CHECK (tenant_id = '00000000-0000-0000-0000-000000000003'::uuid),
    CONSTRAINT ca_signer_handle_claims_hash_chk
        CHECK (handle_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ca_signer_handle_claims_state_chk
        CHECK ((state = 'claimed' AND owner_tenant_id IS NOT NULL AND owner_ceremony_id IS NOT NULL)
            OR (state = 'retired' AND owner_tenant_id IS NULL AND owner_ceremony_id IS NULL))
);
ALTER TABLE ca_signer_handle_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE ca_signer_handle_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY ca_signer_handle_claims_isolation ON ca_signer_handle_claims
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE ON ca_signer_handle_claims TO trstctl_app;
CREATE INDEX ca_signer_handle_claims_owner_idx
    ON ca_signer_handle_claims (tenant_id, owner_tenant_id)
    WHERE owner_tenant_id IS NOT NULL;

-- Existing authorities already own their handles. A duplicate across tenants
-- fails migration rather than blessing an already-shared signing key.
INSERT INTO ca_signer_handle_claims
    (tenant_id, handle_sha256, owner_tenant_id, owner_ceremony_id)
SELECT '00000000-0000-0000-0000-000000000003'::uuid,
       encode(sha256(convert_to(signer_handle, 'UTF8')), 'hex'), tenant_id, id
  FROM ca_authorities
 WHERE signer_handle IS NOT NULL AND signer_handle <> '';
