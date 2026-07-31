-- CBOM events are projected both synchronously for read-your-write responses and
-- by the at-least-once live tail. Keep the newest stream sequence on each fact so
-- a delayed older observation cannot overwrite a later migration or rollback.
--
-- When a migration converges a weak fact onto a desired fact that is already in
-- the inventory, the weak row becomes an inactive tombstone instead of being
-- deleted. The tombstone retains the selected fact's id and sequence fence, so a
-- duplicate observation cannot resurrect it and an exact rollback can reactivate
-- it from immutable event evidence.
ALTER TABLE crypto_assets
    ADD COLUMN event_sequence bigint NOT NULL DEFAULT 0 CHECK (event_sequence >= 0),
    ADD COLUMN is_active boolean NOT NULL DEFAULT true;
