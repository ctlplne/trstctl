-- CT watchlist replacement (AUD-70). The discovery source event is the
-- authority for the active set. Checkpoint/domain rows remain in place when
-- removed so operators retain audit history, but active-only readers and
-- schedulers cannot let a retired endpoint poison a later run.

ALTER TABLE ct_watched_domains
    ADD COLUMN active boolean NOT NULL DEFAULT true,
	ADD COLUMN activated_at timestamptz,
    ADD COLUMN retired_at timestamptz;

UPDATE ct_watched_domains
   SET activated_at = created_at
 WHERE activated_at IS NULL;

ALTER TABLE ct_watched_domains
    ADD CONSTRAINT ct_watched_domains_activated_at_present
        CHECK (activated_at IS NOT NULL) NOT VALID;

ALTER TABLE ct_watched_domains
    VALIDATE CONSTRAINT ct_watched_domains_activated_at_present;

ALTER TABLE ct_watched_domains
    ALTER COLUMN activated_at SET DEFAULT now(),
    ALTER COLUMN activated_at SET NOT NULL;

ALTER TABLE ct_watched_domains
    DROP CONSTRAINT ct_watched_domains_activated_at_present;

ALTER TABLE ct_log_checkpoints
    ADD COLUMN active boolean NOT NULL DEFAULT true,
	ADD COLUMN activated_at timestamptz,
    ADD COLUMN retired_at timestamptz,
    ADD COLUMN last_poll_status text NOT NULL DEFAULT 'never',
    ADD COLUMN last_poll_error text NOT NULL DEFAULT '',
    ADD COLUMN last_polled_at timestamptz,
    ADD CONSTRAINT ct_log_checkpoints_poll_status_check
        CHECK (last_poll_status IN ('never', 'succeeded', 'failed'));

UPDATE ct_log_checkpoints
   SET activated_at = updated_at
 WHERE activated_at IS NULL;

ALTER TABLE ct_log_checkpoints
    ADD CONSTRAINT ct_log_checkpoints_activated_at_present
        CHECK (activated_at IS NOT NULL) NOT VALID;

ALTER TABLE ct_log_checkpoints
    VALIDATE CONSTRAINT ct_log_checkpoints_activated_at_present;

ALTER TABLE ct_log_checkpoints
    ALTER COLUMN activated_at SET DEFAULT now(),
    ALTER COLUMN activated_at SET NOT NULL;

ALTER TABLE ct_log_checkpoints
    DROP CONSTRAINT ct_log_checkpoints_activated_at_present;
