-- A240: a single-phase rotation (the provider invalidates the current
-- credential the moment it issues the next one) runs only when its request or
-- schedule acknowledges that consumers fail until they read the new version.
-- The acknowledgement is part of the immutable queued event and is projected
-- here so the command and schedule views show it.

ALTER TABLE secret_static_rotation_commands
    ADD COLUMN IF NOT EXISTS single_phase_acknowledged boolean NOT NULL DEFAULT false;

ALTER TABLE secret_rotation_schedules
    ADD COLUMN IF NOT EXISTS single_phase_acknowledged boolean NOT NULL DEFAULT false;
