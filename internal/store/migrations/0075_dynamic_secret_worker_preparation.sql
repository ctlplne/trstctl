-- 0075_dynamic_secret_worker_preparation.sql -- persist locally prepared key
-- material before the outbox worker performs the provider mutation.
--
-- The value is envelope ciphertext. Keeping it on the event-projected lease
-- lets a crashed worker retry the identical provider identity without asking
-- the served request goroutine to call provider code (AN-6/AN-8).

ALTER TABLE dynamic_secret_leases
    ADD COLUMN IF NOT EXISTS sealed_preparation bytea NOT NULL DEFAULT ''::bytea;
