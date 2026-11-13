-- A237-L7: a scoped sync's own drift-check interval. The reconciler re-plans
-- an auto or approved definition when its source or its author's grants
-- change, and otherwise every drift interval; 0 keeps the deployment's
-- 15-minute default, else 60 s to 24 h. Existing definitions keep the default.
-- The column carries a constant default (no rewrite), and its check is added
-- NOT VALID: every existing row holds the default the check admits.
ALTER TABLE secret_scoped_syncs
    ADD COLUMN IF NOT EXISTS reconcile_interval_seconds integer NOT NULL DEFAULT 0;
ALTER TABLE secret_scoped_syncs
    DROP CONSTRAINT IF EXISTS secret_scoped_syncs_reconcile_interval_check;
ALTER TABLE secret_scoped_syncs
    ADD CONSTRAINT secret_scoped_syncs_reconcile_interval_check
        CHECK (reconcile_interval_seconds = 0 OR reconcile_interval_seconds BETWEEN 60 AND 86400) NOT VALID;
