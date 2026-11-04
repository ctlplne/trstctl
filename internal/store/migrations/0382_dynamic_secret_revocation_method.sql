-- N3: how an AWS STS lease's completed revocation ended its session.
-- deny_policy: an inline policy on the role, read back before completion,
-- denies that one session (aws:userid) before its expiry, and AWS enforces it.
-- native_expiry: the session lapsed at its own expiry. Empty for providers
-- that remove the credential themselves. Projection of the method on
-- dynsecret.lease.revocation_completed; a retried revocation clears it.

ALTER TABLE dynamic_secret_leases
    ADD COLUMN IF NOT EXISTS revocation_method text NOT NULL DEFAULT ''
        CHECK (revocation_method IN ('', 'deny_policy', 'native_expiry'));
