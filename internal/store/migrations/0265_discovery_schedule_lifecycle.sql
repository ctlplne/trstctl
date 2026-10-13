-- Keep discovery schedule history while allowing operators to stop future runs.
-- The event sequence columns make replay and snapshot restore preserve the
-- newest control decision when an older declaration is projected later.
ALTER TABLE discovery_schedules
    ADD COLUMN config_event_sequence bigint NOT NULL DEFAULT 0,
    ADD COLUMN control_event_sequence bigint NOT NULL DEFAULT 0,
    ADD COLUMN retired_at timestamptz;

ALTER TABLE discovery_schedules
    ADD CONSTRAINT discovery_schedules_retired_disabled
    CHECK (retired_at IS NULL OR NOT enabled);

ALTER TABLE discovery_schedules
    ADD CONSTRAINT discovery_schedules_event_sequences_nonnegative
    CHECK (config_event_sequence >= 0 AND control_event_sequence >= 0);
