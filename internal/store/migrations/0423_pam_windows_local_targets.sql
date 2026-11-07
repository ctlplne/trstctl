-- A268: a Windows local administrator account vaulted in an application secret
-- that its native provider rotates on the enrolled host. It is checked out,
-- never opened as a session.
ALTER TABLE pam_targets DROP CONSTRAINT IF EXISTS pam_targets_target_type_check;
ALTER TABLE pam_targets ADD CONSTRAINT pam_targets_target_type_check
    CHECK (target_type IN ('postgres', 'ssh', 'redis', 'mysql', 'mongodb', 'clickhouse', 'kubernetes', 'snowflake', 'aws', 'gcp', 'azure', 'aws-console', 'rdp', 'windows_local'));
