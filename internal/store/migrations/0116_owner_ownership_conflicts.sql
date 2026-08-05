-- I2: ownership disagreements are recorded, not resolved silently.
--
-- Split from 0115 deliberately. 0115 adds nullable provenance columns and
-- writes no values; this creates a new table. Keeping them apart means each
-- migration does one thing, and it stops the SCHEMA-002 tripwire matching an
-- ALTER ... ADD COLUMN in one statement against a DEFAULT in an unrelated one —
-- a heuristic worth satisfying honestly rather than working around, since its
-- job is to catch migrations that quietly rewrite live rows.

-- Conflicts are recorded, not resolved silently.
--
-- The acceptance says "with conflict resolution", and the resolution this
-- system can honestly offer is NOT last-writer-wins: a bulk import must never
-- quietly overwrite ownership a human attested, because the attestation is the
-- scarcer and more expensive fact. So a disagreement becomes a row somebody can
-- look at, with both sides recorded, rather than a field that changed.
CREATE TABLE IF NOT EXISTS owner_ownership_conflicts (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid NOT NULL,
    owner_id          uuid NOT NULL,
    -- The field the two sources disagree about, e.g. "application_id".
    field             text NOT NULL,
    -- What is stored now, and where it came from.
    current_value     text NOT NULL DEFAULT '',
    current_source    text NOT NULL DEFAULT '',
    -- What the incoming source claims.
    incoming_value    text NOT NULL DEFAULT '',
    incoming_source   text NOT NULL DEFAULT '',
    incoming_ref      text NOT NULL DEFAULT '',
    -- Whether the stored side was human-attested at the time of the conflict.
    -- This is why the import declined: attested ownership is not overwritten by
    -- a spreadsheet.
    current_attested  boolean NOT NULL DEFAULT false,
    detected_at       timestamptz NOT NULL DEFAULT now(),
    resolved_at       timestamptz,
    resolution        text NOT NULL DEFAULT ''
);

-- AN-1: every table carries tenant_id and every query filters on it.
ALTER TABLE owner_ownership_conflicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE owner_ownership_conflicts FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS owner_ownership_conflicts_tenant_isolation ON owner_ownership_conflicts;
CREATE POLICY owner_ownership_conflicts_tenant_isolation ON owner_ownership_conflicts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- Open conflicts are what an operator queues on, so that is the indexed access
-- path rather than the whole table.
CREATE INDEX IF NOT EXISTS owner_ownership_conflicts_open_idx
    ON owner_ownership_conflicts (tenant_id, detected_at DESC)
    WHERE resolved_at IS NULL;

-- The application role reads, records, and resolves conflicts, and offboarding a
-- tenant deletes them — so all four, matching every other tenant-scoped table.
GRANT SELECT, INSERT, UPDATE, DELETE ON owner_ownership_conflicts TO trstctl_app;
