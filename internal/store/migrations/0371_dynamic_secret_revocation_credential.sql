-- A239: an OAuth access token is revoked by presenting it to the authorization
-- server (RFC 7009). When such a lease is revoked, its sealed credential moves
-- here instead of being discarded, and is wiped when the provider-side
-- revocation completes. Envelope ciphertext bound to the lease, exactly as
-- sealed_credential is; never plaintext. Other leases keep it empty, and only a
-- revoked lease whose revocation has not completed may carry one.
ALTER TABLE dynamic_secret_leases
    ADD COLUMN IF NOT EXISTS revocation_sealed_credential bytea NOT NULL DEFAULT ''::bytea;
ALTER TABLE dynamic_secret_leases
    ADD CONSTRAINT dynamic_secret_leases_revocation_credential_chk
        CHECK (octet_length(revocation_sealed_credential) = 0
               OR (state = 'revoked' AND revocation_status <> 'completed'));
