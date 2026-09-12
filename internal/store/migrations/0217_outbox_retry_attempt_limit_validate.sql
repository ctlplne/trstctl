-- Validate with PostgreSQL's weaker validation lock after the short metadata
-- migration commits. Existing rows retain their ordinary automatic retry limit.
ALTER TABLE outbox VALIDATE CONSTRAINT outbox_retry_attempt_limit_nonnegative;
