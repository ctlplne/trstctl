-- Discovery findings keep one row per observed credential per source across
-- repeated runs. A later run that sees the same listener or secret refreshes the
-- row (latest run, last_seen_at, seen_count) instead of opening a duplicate, so
-- the console and the open-finding counts describe the estate once. The
-- projection always writes the observation times explicitly; the defaults only
-- keep direct fixture inserts valid. projection_event_sequence remembers the
-- newest immutable event applied to the row so catch-up replay of an already
-- applied observation is a no-op (0 = written before this column existed).
ALTER TABLE discovery_findings
    ADD COLUMN IF NOT EXISTS first_seen_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_seen_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS seen_count integer NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS projection_event_sequence bigint NOT NULL DEFAULT 0;
UPDATE discovery_findings SET first_seen_at = discovered_at, last_seen_at = discovered_at;
ALTER TABLE discovery_findings
    ADD CONSTRAINT discovery_findings_seen_count_positive CHECK (seen_count >= 1);
