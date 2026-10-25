-- Owner decision 2026-10-24: a certificate issued before its issuing path
-- recorded custody gets its key origin derived from its retained issuance
-- event where that event proves it. The rule and the proving event stay beside
-- the origin, so a derived origin is never read as one recorded at issuance.
ALTER TABLE certificates
    ADD COLUMN key_origin_derivation text NOT NULL DEFAULT '',
    ADD COLUMN key_origin_proof_event_id text NOT NULL DEFAULT '';

-- Separate from applied_seq: an older binary can advance projection without
-- deriving the origins its retained certificate events prove.
ALTER TABLE projection_checkpoint
    ADD COLUMN key_origin_derivation_checked_through bigint NOT NULL DEFAULT 0
    CHECK (key_origin_derivation_checked_through >= 0);
