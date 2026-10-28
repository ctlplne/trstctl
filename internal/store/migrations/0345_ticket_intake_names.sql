-- A225: keep existing provider schedules as default while adding named sources.
ALTER TABLE ticket_intake_schedules
    ADD COLUMN name text NOT NULL DEFAULT 'default',
    ADD COLUMN owner_field text NOT NULL DEFAULT '',
    ADD CONSTRAINT ticket_intake_schedule_name_format
        CHECK (name ~ '^[a-z0-9][a-z0-9_-]{0,39}$') NOT VALID;

ALTER TABLE ticket_intake_schedules VALIDATE CONSTRAINT ticket_intake_schedule_name_format;
