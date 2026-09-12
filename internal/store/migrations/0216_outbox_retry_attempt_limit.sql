-- One explicit recovery grant permits one additional claim without resetting
-- cumulative attempts or changing the original receiver command. Zero retains
-- the ordinary worker-configured automatic retry limit. PostgreSQL 14+ applies
-- this constant default as metadata, without rewriting existing outbox rows.
ALTER TABLE outbox ADD COLUMN retry_attempt_limit integer NOT NULL DEFAULT 0;
ALTER TABLE outbox ADD CONSTRAINT outbox_retry_attempt_limit_nonnegative
    CHECK (retry_attempt_limit >= 0) NOT VALID;
