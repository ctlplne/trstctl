-- A272: a break-glass identity provider administrator account, vaulted in an
-- application secret its provider rotates; released only through emergency
-- access, never opened as a session.
ALTER TABLE pam_targets DROP CONSTRAINT IF EXISTS pam_targets_target_type_check;
ALTER TABLE pam_targets ADD CONSTRAINT pam_targets_target_type_check
    CHECK (target_type IN ('postgres', 'ssh', 'redis', 'mysql', 'mongodb', 'clickhouse', 'kubernetes', 'snowflake', 'aws', 'gcp', 'azure', 'aws-console', 'rdp', 'windows_local', 'netdevice', 'account', 'breakglass'));
