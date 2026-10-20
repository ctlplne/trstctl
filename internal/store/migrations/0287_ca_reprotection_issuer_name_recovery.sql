-- The event log is the authority for a re-protected leaf's successor CA.
-- Track the finite event-type replay used to correct names projected by older
-- binaries without replaying the entire log on every warm restart.
ALTER TABLE projection_checkpoint
    ADD COLUMN ca_reprotection_name_checked_through bigint
    CHECK (ca_reprotection_name_checked_through >= 0);
