-- A provider call may finish after the requested lease deadline. The actual
-- issue time must remain accurate so the expiry worker can immediately revoke
-- that native credential. The requested deadline still cannot exceed the hard
-- ceiling; pending and failed requests retain the original time ordering.
ALTER TABLE dynamic_secret_leases
    DROP CONSTRAINT dynamic_secret_leases_expiry_chk;
ALTER TABLE dynamic_secret_leases
    ADD CONSTRAINT dynamic_secret_leases_expiry_chk
        CHECK (expires_at <= hard_expires_at
               AND (state IN ('active', 'revoked') OR issued_at <= expires_at));
