-- A273: internal web admin consoles. A webconsole target vaults the account
-- its gateway signs in to the console as and names the console's route; an
-- access template names how the gateway signs in; a session keeps the
-- sign-in its reviewers approved.
ALTER TABLE pam_targets DROP CONSTRAINT IF EXISTS pam_targets_target_type_check;
ALTER TABLE pam_targets ADD CONSTRAINT pam_targets_target_type_check
    CHECK (target_type IN ('postgres', 'ssh', 'redis', 'mysql', 'mongodb', 'clickhouse', 'kubernetes', 'snowflake', 'aws', 'gcp', 'azure', 'aws-console', 'rdp', 'windows_local', 'netdevice', 'account', 'breakglass', 'webconsole'));
ALTER TABLE pam_targets ADD COLUMN web_route jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(web_route) = 'object');
ALTER TABLE pam_access_templates ADD COLUMN web_sign_in jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(web_sign_in) = 'object');
ALTER TABLE pam_sessions ADD COLUMN web_sign_in jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(web_sign_in) = 'object');
