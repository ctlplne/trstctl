-- A ticket relay may redeem a tenant secret only for the exact configuration
-- revision whose actor still holds read authority. Historical rows are
-- unattributed and fail closed until an authorized operator saves them again.
ALTER TABLE ticket_intake_schedules
    ADD COLUMN configured_by text NOT NULL DEFAULT '',
    ADD COLUMN config_revision text NOT NULL DEFAULT '';
