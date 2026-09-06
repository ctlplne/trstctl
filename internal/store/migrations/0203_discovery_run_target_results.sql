-- A discovery run keeps every assigned target's outcome (found / failed /
-- blocked / rejected with its reason) as projected from the immutable completion
-- event, so a partial run says which listener failed and why. CT-log monitoring
-- keeps its own per-log read model; this column carries the other kinds.
ALTER TABLE discovery_runs
    ADD COLUMN IF NOT EXISTS target_results jsonb NOT NULL DEFAULT '[]'::jsonb;
