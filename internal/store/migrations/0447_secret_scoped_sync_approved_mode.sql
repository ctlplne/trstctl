-- A237-L1: approval-gated convergence. An approved scoped sync is re-planned like
-- an auto one when its sources change, but a plan with changes is applied only
-- once the tenant's required number of distinct approvers approve that exact
-- plan; a manual apply of it waits for the same approval.
ALTER TABLE secret_scoped_syncs DROP CONSTRAINT IF EXISTS secret_scoped_syncs_mode_check;
ALTER TABLE secret_scoped_syncs
    ADD CONSTRAINT secret_scoped_syncs_mode_check CHECK (mode IN ('manual', 'auto', 'approved'));
