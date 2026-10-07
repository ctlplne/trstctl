-- The last inventory source is mutable observation provenance. Retain the
-- authenticated external issuance authority independently for ARI and recovery.
ALTER TABLE certificates ADD COLUMN issuing_external_ca_id text NOT NULL DEFAULT '';

-- Separate from applied_seq: an older binary can advance projection without
-- checking whether pre-upgrade external events need provenance recovery.
ALTER TABLE projection_checkpoint
    ADD COLUMN external_issuer_checked_through bigint NOT NULL DEFAULT 0
    CHECK (external_issuer_checked_through >= 0);
