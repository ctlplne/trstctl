-- A256: a PAM target may be a Redis database, whose sessions are delivered
-- only through an access gateway (the broker refuses one without a gateway
-- binding). The check names each target type the broker serves.
ALTER TABLE pam_targets DROP CONSTRAINT IF EXISTS pam_targets_target_type_check;
ALTER TABLE pam_targets
    ADD CONSTRAINT pam_targets_target_type_check
    CHECK (target_type IN ('postgres', 'ssh', 'redis'));
