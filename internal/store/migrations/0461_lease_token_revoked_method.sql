-- OD-5 (N3-L4): a GitHub App or OAuth lease's completed revocation names how
-- its token ended, as an AWS STS lease's does (0382): token_revoked when the
-- provider confirmed the token ended when it was presented (GitHub's
-- DELETE /installation/token, an RFC 7009 revocation endpoint), native_expiry
-- when it lapsed at its own expiry. The column's check admits the new value;
-- existing rows hold '', deny_policy or native_expiry, which it still admits.

ALTER TABLE dynamic_secret_leases
    DROP CONSTRAINT IF EXISTS dynamic_secret_leases_revocation_method_check;

ALTER TABLE dynamic_secret_leases
    ADD CONSTRAINT dynamic_secret_leases_revocation_method_check
        CHECK (revocation_method IN ('', 'deny_policy', 'native_expiry', 'token_revoked')) NOT VALID;

ALTER TABLE dynamic_secret_leases
    VALIDATE CONSTRAINT dynamic_secret_leases_revocation_method_check;
