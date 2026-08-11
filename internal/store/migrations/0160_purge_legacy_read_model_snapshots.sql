-- Read-model snapshots are disposable projections of the AN-2 event log. Before
-- format 22, one tenant row could survive after a privacy erasure removed a
-- neighbor, and its JSON payload could retain the raw subject even though current
-- restore code correctly ignored that old format. Ignoring is not erasure: remove
-- the old heap wholesale during upgrade so no pre-v22 payload remains in the live
-- snapshot relation.
--
-- TRUNCATE is intentional. Every row present when this binary first upgrades is
-- from a format that cannot prove one complete all-tenant generation. A full
-- event replay recreates the read model, and the periodic worker later publishes
-- a new format-22 generation. No snapshot is source-of-truth state (AN-2).

TRUNCATE TABLE read_model_snapshots;

-- A rolling old replica must not repopulate the table after the new replica's
-- one-time purge. Old snapshot workers fail only this disposable cache write;
-- event projection and serving continue, and format 22 can replace the cache.
ALTER TABLE read_model_snapshots
    ADD CONSTRAINT read_model_snapshots_format_floor_v22
    CHECK (format_version >= 22);
