-- A264: keep verified actor/version evidence separate from phase ordering.
ALTER TABLE cloud_machine_changes ADD COLUMN adoption jsonb;
ALTER TABLE cloud_machine_changes DROP CONSTRAINT cloud_machine_changes_state_check;
ALTER TABLE cloud_machine_changes ADD CONSTRAINT cloud_machine_changes_state_check
    CHECK (state IN ('awaiting_approval','queued','preparing_replacement','waiting_adoption','verified','failed'));

ALTER TABLE secret_static_rotation_commands ADD COLUMN cloud_change_id uuid;
