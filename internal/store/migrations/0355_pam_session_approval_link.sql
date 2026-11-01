-- G1: a PAM session records the operation approval its activation consumed, so
-- the access graph can say who approved a person's or workload's access to a
-- database or host. The link comes from the session's started event; sessions
-- started before this column read '' (approval link not recorded).
ALTER TABLE pam_sessions
    ADD COLUMN IF NOT EXISTS approval_request_id text NOT NULL DEFAULT '';
