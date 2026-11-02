-- A237 part b: continuous scoped sync. An auto definition is re-planned when its
-- sources change (and on a drift interval) and applied when nothing in the plan
-- is blocked; a manual one waits for a reviewed apply. The last reconcile and the
-- source set it saw are recorded on the definition.
ALTER TABLE secret_scoped_syncs
    ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT 'manual' CHECK (mode IN ('manual', 'auto')),
    ADD COLUMN IF NOT EXISTS source_digest text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_reconcile_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_reconcile_status text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_reconcile_reason text NOT NULL DEFAULT '';
