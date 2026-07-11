-- 0077_idempotency_request_binding.sql -- bind credential-bearing durable
-- mutations to the authenticated caller and canonical command before their
-- independently durable receiver runs.
--
-- Historical completed rows cannot be reconstructed safely because their raw
-- request bodies and principals were deliberately not retained. They keep the
-- empty default and therefore fail closed if a newly bound endpoint sees an old
-- key. New bound calls persist only a SHA-256 digest, never request secrets.

ALTER TABLE idempotency_keys
    ADD COLUMN IF NOT EXISTS request_binding text NOT NULL DEFAULT '';
