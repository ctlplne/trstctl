-- SPDX-License-Identifier: BUSL-1.1
-- A277: a high-risk access template requires a fresh sign-in before a session
-- or credential release through it: the sign-in may be at most this many
-- seconds old. Existing templates keep their meaning: no fresh sign-in.
ALTER TABLE pam_access_templates ADD COLUMN IF NOT EXISTS reauthenticate_within_seconds integer NOT NULL DEFAULT 0
    CHECK (reauthenticate_within_seconds = 0 OR reauthenticate_within_seconds BETWEEN 60 AND 3600);
