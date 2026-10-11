-- 0258: event-projected pause, resume and retirement of secret rotation schedules.
-- A control event changes eligibility only. It must not rewrite the due-edge
-- tuple or predecessor that a previously claimed command will terminalize.
ALTER TABLE secret_rotation_schedules
    ADD COLUMN IF NOT EXISTS control_event_sequence bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS retired_at timestamptz;

ALTER TABLE secret_rotation_schedules
    ADD CONSTRAINT secret_rotation_schedules_control_sequence_chk
        CHECK (control_event_sequence >= 0),
    ADD CONSTRAINT secret_rotation_schedules_retired_disabled_chk
        CHECK (retired_at IS NULL OR NOT enabled);
