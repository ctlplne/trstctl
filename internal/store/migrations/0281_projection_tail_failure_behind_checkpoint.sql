-- The relational applied_seq can move ahead of the shared JetStream consumer:
-- a command may project an event before that consumer ACKs it. A failed older
-- consumer message remains unresolved even when applied_seq is higher. Only an
-- explicit successful replay through Store.AdvanceProjectionCheckpoint may clear
-- its failure marker. The old trigger treated applied_seq as proof of the ACK.

DROP TRIGGER projection_checkpoint_normalize_failure ON projection_checkpoint;
DROP FUNCTION projection_checkpoint_normalize_failure();

ALTER TABLE projection_checkpoint
    DROP CONSTRAINT projection_checkpoint_failure_shape_chk,
    ADD CONSTRAINT projection_checkpoint_failure_shape_chk CHECK (
        (failed_seq IS NULL AND last_error IS NULL AND failed_at IS NULL)
        OR
        (failed_seq > 0 AND last_error IS NOT NULL
            AND octet_length(last_error) BETWEEN 1 AND 2048
            AND failed_at IS NOT NULL)
    );
