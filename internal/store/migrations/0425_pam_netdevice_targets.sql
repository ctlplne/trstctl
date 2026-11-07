-- A270: a network device's vaulted account, reached over SSH through its
-- access gateway, which signs in with the account's password.
ALTER TABLE pam_targets DROP CONSTRAINT IF EXISTS pam_targets_target_type_check;
ALTER TABLE pam_targets ADD CONSTRAINT pam_targets_target_type_check
    CHECK (target_type IN ('postgres', 'ssh', 'redis', 'mysql', 'mongodb', 'clickhouse', 'kubernetes', 'snowflake', 'aws', 'gcp', 'azure', 'aws-console', 'rdp', 'windows_local', 'netdevice'));
