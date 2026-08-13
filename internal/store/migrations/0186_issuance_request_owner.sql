-- AUD-78: bind first-class self-service issuance requests to the tenant owner
-- accountable for the resulting credential.
--
-- Historical ticket/API events did not carry an owner, so this column remains
-- nullable for replay compatibility. The served self-service mutation requires
-- and validates it before append; NULL therefore means "old event did not say",
-- not a guessed owner.
ALTER TABLE issuance_requests
    ADD COLUMN IF NOT EXISTS owner_id uuid;

-- The composite key is the storage-layer tenant fence. A valid owner UUID from
-- another tenant must look exactly like a missing owner and must never become a
-- cross-tenant relationship.
ALTER TABLE issuance_requests
    DROP CONSTRAINT IF EXISTS issuance_requests_owner_fk;
ALTER TABLE issuance_requests
    ADD CONSTRAINT issuance_requests_owner_fk
    FOREIGN KEY (tenant_id, owner_id)
    REFERENCES owners (tenant_id, id)
    NOT VALID;
ALTER TABLE issuance_requests
    VALIDATE CONSTRAINT issuance_requests_owner_fk;
