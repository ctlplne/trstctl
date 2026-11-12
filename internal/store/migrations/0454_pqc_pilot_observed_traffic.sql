-- X3-L5: a PQC pilot can require observed traffic. A wave whose probe passed
-- then waits, as awaiting_traffic, until an observer agent has seen real
-- clients connect at every target after its probe, or its window ends; the
-- gate's evidence stays on the wave's results, and traffic_checked_at
-- records when the gate closed. Projected from pqc.pilot.started and
-- pqc.pilot.wave_traffic_checked. A pilot started before this requires none,
-- as before; columns with constant defaults rewrite no rows.
ALTER TABLE pqc_pilots
    ADD COLUMN IF NOT EXISTS require_observed_traffic boolean NOT NULL DEFAULT false;
ALTER TABLE pqc_pilots
    ADD COLUMN IF NOT EXISTS observed_traffic_window_seconds integer NOT NULL DEFAULT 0;
ALTER TABLE pqc_pilots
    ADD CONSTRAINT pqc_pilots_traffic_window_chk CHECK (
        observed_traffic_window_seconds BETWEEN 0 AND 604800
        AND (require_observed_traffic OR observed_traffic_window_seconds = 0));
ALTER TABLE pqc_pilot_waves
    ADD COLUMN IF NOT EXISTS traffic_checked_at timestamptz;
ALTER TABLE pqc_pilot_waves DROP CONSTRAINT IF EXISTS pqc_pilot_waves_status_chk;
ALTER TABLE pqc_pilot_waves
    ADD CONSTRAINT pqc_pilot_waves_status_chk
    CHECK (status IN ('pending', 'probing', 'awaiting_traffic', 'assessed', 'skipped'));
