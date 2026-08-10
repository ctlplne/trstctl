-- 0136_fleet_reissuance_cursor.sql -- durable canary-first fleet execution.
--
-- The cursor and halt reason are projected from incident.fleet_reissuance.recorded
-- events. They make pause, resume, canary halt, and restart recovery command-side
-- facts instead of labels calculated only when an operator reads the run.

ALTER TABLE incident_fleet_reissuance_runs
    ADD COLUMN IF NOT EXISTS next_batch_index integer NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS halted_reason text NOT NULL DEFAULT '';
