-- 0078_dynamic_secret_request_binding.sql -- keep the authenticated issue
-- command binding for the full provider-credential lifetime.
--
-- The general idempotency response cache is intentionally garbage-collected.
-- An active dynamic credential can outlive that cache, so its projected row
-- retains the non-secret SHA-256 request binding and refuses to open the sealed
-- credential for a different principal/command after cache expiry.

ALTER TABLE dynamic_secret_leases
    ADD COLUMN IF NOT EXISTS request_binding text NOT NULL DEFAULT '';
