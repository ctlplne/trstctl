-- Projection-tail health (AUD-103) lives beside the one global projection
-- checkpoint. A poison event is not tenant-local: it stops the global ordered
-- stream, so adding tenant_id here would let one tenant view the same stalled
-- cursor as healthy while another views it as failed.
--
-- The three nullable fields move together. NULL means the tail has no unresolved
-- failure. A populated row names the earliest failed stream sequence, a bounded
-- diagnostic, and when the worker last saw that failure. PostgreSQL clears all
-- three when applied_seq reaches failed_seq. The trigger is deliberate mixed-
-- version protection: a pre-health binary updates only applied_seq, so relying on
-- new application SQL would leave applied_seq >= failed_seq visibly stale until
-- every replica was upgraded.

ALTER TABLE projection_checkpoint
    ADD COLUMN failed_seq bigint,
    ADD COLUMN last_error text,
    ADD COLUMN failed_at timestamptz,
    ADD CONSTRAINT projection_checkpoint_failure_shape_chk CHECK (
        (failed_seq IS NULL AND last_error IS NULL AND failed_at IS NULL)
        OR
        (failed_seq > 0 AND failed_seq > applied_seq AND last_error IS NOT NULL
            AND octet_length(last_error) BETWEEN 1 AND 2048
            AND failed_at IS NOT NULL)
    );

CREATE FUNCTION projection_checkpoint_normalize_failure()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.failed_seq IS NOT NULL AND NEW.applied_seq >= NEW.failed_seq THEN
        NEW.failed_seq := NULL;
        NEW.last_error := NULL;
        NEW.failed_at := NULL;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER projection_checkpoint_normalize_failure
BEFORE INSERT OR UPDATE ON projection_checkpoint
FOR EACH ROW
EXECUTE FUNCTION projection_checkpoint_normalize_failure();
