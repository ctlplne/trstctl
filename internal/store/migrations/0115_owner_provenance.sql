-- I2: where an ownership claim came from, and when that source last said it.
--
-- Ownership today has no provenance at all. Every owner row looks identical
-- whether a human attested it, an operator typed it once in 2024, or a bulk
-- import guessed it from a spreadsheet column — and the epic's acceptance turns
-- on exactly that distinction: a CMDB CI mapping is only useful if you can tell
-- which side of a disagreement came from where.
--
-- An estate that predates this has owners whose origin nobody can reconstruct,
-- and inventing one would be worse than admitting it.

-- NULLABLE with no default, matching 0112 and for the reason 0112 gives: unknown
-- has to stay distinguishable from known-and-empty. A NOT NULL DEFAULT '' would
-- stamp every pre-existing row with a value that reads like a recorded answer,
-- and the whole point of provenance is telling a recorded origin from an absent
-- one.
ALTER TABLE owners
    ADD COLUMN IF NOT EXISTS ownership_source text,
    ADD COLUMN IF NOT EXISTS ownership_source_ref text,
    ADD COLUMN IF NOT EXISTS ownership_source_observed_at timestamptz;

COMMENT ON COLUMN owners.ownership_source IS
    'Where this ownership claim came from: NULL (unknown, pre-dates provenance), "manual", "csv-import", or "cmdb". NULL is never "manual" — an unrecorded origin is not evidence of a human.';
COMMENT ON COLUMN owners.ownership_source_ref IS
    'The identifier within that source: a CMDB CI sys_id, an import batch id. Lets a disagreement be traced back to the row that caused it.';
COMMENT ON COLUMN owners.ownership_source_observed_at IS
    'When the source last asserted this. NULL means never observed from a source, which is distinct from observed long ago.';
