-- Q6-L10: a decoy the watcher cannot read records a monitoring gap, since
-- when and why, set and cleared by honeytoken.watch_gap events. Both columns
-- are nullable so a snapshot taken before them restores unchanged.
ALTER TABLE honey_tokens
    ADD COLUMN IF NOT EXISTS watch_gap_since timestamptz,
    ADD COLUMN IF NOT EXISTS watch_gap_reason text;
