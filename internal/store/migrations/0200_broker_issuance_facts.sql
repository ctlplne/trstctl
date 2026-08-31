-- Public broker command facts are part of the one shared certificate inventory.
-- NULL is honest legacy/unrecorded/retained-away metadata, not an empty success.
-- Existing certificate tenant RLS and privileges apply unchanged (AN-1).
ALTER TABLE certificates ADD COLUMN broker_issuance jsonb;
ALTER TABLE certificates ADD CONSTRAINT certificates_broker_issuance_object
    CHECK (broker_issuance IS NULL OR jsonb_typeof(broker_issuance) = 'object') NOT VALID;
-- Validation and index construction happen separately so a populated inventory
-- is not scanned while this additive transaction holds its short DDL lock.
