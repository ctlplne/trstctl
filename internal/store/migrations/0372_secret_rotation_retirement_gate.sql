-- A240: a static rotation's retirement gate. A command may name the consumers
-- whose verified delivery report (A238: secret_deliveries.verified_version, the
-- version the consumer's application proved it uses) must reach the command's
-- result version before the predecessor is retired, and the approved deadline,
-- in seconds after verification, at which it retires regardless. The principal
-- that approved the deadline and the projected retire_not_before keep the
-- deadline visible. Schedules carry the same policy to every command they queue.

ALTER TABLE secret_static_rotation_commands
    ADD COLUMN IF NOT EXISTS consumers text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS retire_after_seconds integer NOT NULL DEFAULT 0 CHECK (retire_after_seconds >= 0),
    ADD COLUMN IF NOT EXISTS retire_approved_by text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS retire_not_before timestamptz;

ALTER TABLE secret_rotation_schedules
    ADD COLUMN IF NOT EXISTS consumers text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS retire_after_seconds integer NOT NULL DEFAULT 0 CHECK (retire_after_seconds >= 0);
