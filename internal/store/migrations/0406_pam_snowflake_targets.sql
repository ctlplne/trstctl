-- A263: Snowflake SQL API accounts use the existing gateway-only provider
-- lifecycle. Preserve every prior target type and all existing rows/RLS.
ALTER TABLE pam_targets DROP CONSTRAINT IF EXISTS pam_targets_target_type_check;
ALTER TABLE pam_targets
    ADD CONSTRAINT pam_targets_target_type_check
    CHECK (target_type IN ('postgres', 'ssh', 'redis', 'mysql', 'mongodb', 'clickhouse', 'kubernetes', 'snowflake'));
