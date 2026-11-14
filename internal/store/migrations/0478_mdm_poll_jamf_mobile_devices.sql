-- N9-L1: a Jamf poll schedule can have the network relay read Jamf Pro's
-- mobile device inventory as well as its computers. Off for every existing
-- schedule, so an API role that can read only computers keeps working.
-- Online-safe: adding a column with a constant default rewrites no rows.
ALTER TABLE mdm_poll_schedules
    ADD COLUMN IF NOT EXISTS jamf_mobile_devices boolean NOT NULL DEFAULT false;
