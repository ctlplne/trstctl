-- Q6-L7: a decoy login is watched through its database's session counter,
-- which a statistics reset zeroes, hiding a use before it. The watcher reads
-- pg_stat_database.stats_reset beside the counter and records a reset during
-- the decoy's life as a monitoring gap, once: the latest reset it recorded is
-- kept here, projected from honeytoken.watch_gap.opened's stats_reset_at.

ALTER TABLE honey_tokens
    ADD COLUMN IF NOT EXISTS stats_reset_seen timestamptz;
