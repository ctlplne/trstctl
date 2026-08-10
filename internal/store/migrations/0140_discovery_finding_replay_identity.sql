-- AUD-96: one projected discovery finding can have more than one historical
-- payload ID when an at-least-once run committed part of an attempt and retried.
-- The row keeps every immutable payload ID as a derived alias so replay can pick
-- one deterministic canonical row ID while later triage events that name either
-- legacy ID still resolve to that row.

ALTER TABLE discovery_findings
    ADD COLUMN IF NOT EXISTS recorded_ids uuid[] NOT NULL DEFAULT '{}';

UPDATE discovery_findings
   SET recorded_ids = ARRAY[id]
 WHERE cardinality(recorded_ids) = 0;
