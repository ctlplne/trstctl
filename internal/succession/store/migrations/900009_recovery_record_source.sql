-- Recovery rows created by the threshold-recovery worker are serving copies
-- of immutable nhi.recovery.recorded events. Zero identifies historical rows
-- without a source event; replay never silently treats those as trusted proof.
ALTER TABLE succession_records ADD COLUMN source_sequence bigint NOT NULL DEFAULT 0;
ALTER TABLE succession_records ADD COLUMN proof_event_sequence bigint NOT NULL DEFAULT 0;
ALTER TABLE succession_records ADD COLUMN recovery_leaf bytea;
CREATE UNIQUE INDEX succession_records_source_sequence_uq
    ON succession_records (source_sequence) WHERE source_sequence > 0;
