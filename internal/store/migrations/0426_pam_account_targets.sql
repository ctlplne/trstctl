-- A271: an account its provider rotates in place (ESXi, vCenter single
-- sign-on, Redfish controllers, network devices), vaulted in an application
-- secret. It is checked out, never opened as a session.
ALTER TABLE pam_targets DROP CONSTRAINT IF EXISTS pam_targets_target_type_check;
ALTER TABLE pam_targets ADD CONSTRAINT pam_targets_target_type_check
    CHECK (target_type IN ('postgres', 'ssh', 'redis', 'mysql', 'mongodb', 'clickhouse', 'kubernetes', 'snowflake', 'aws', 'gcp', 'azure', 'aws-console', 'rdp', 'windows_local', 'netdevice', 'account'));
