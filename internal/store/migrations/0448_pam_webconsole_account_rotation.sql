-- A273-O4: a web console session whose target names an in-place account
-- provider rotates the console's account once after the session ends. The
-- session keeps the provider it opened with and, once the rotation is queued,
-- its command.
ALTER TABLE pam_sessions
    ADD COLUMN IF NOT EXISTS account_rotation_provider text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS account_rotation_command_id text NOT NULL DEFAULT '';
