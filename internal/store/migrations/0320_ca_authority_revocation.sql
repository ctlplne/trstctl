-- A CA authority's administrative key revocation (A128): when the isolated
-- signer revoked the authority's key and why. Both are projected from
-- ca.authority.revoked; status = 'revoked' was already the read model's
-- spelling for a revoked authority.
ALTER TABLE ca_authorities
    ADD COLUMN revoked_at timestamptz,
    ADD COLUMN revocation_reason text;
