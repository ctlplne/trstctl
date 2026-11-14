-- P6-L5: a moved leaked secret's history residue is re-checked by every later
-- completed scan of its repository. residue_checked_at and residue_run_id name
-- the scan run that last looked; both stay NULL until one has, and the residue
-- is then as the move recorded it. Online-safe: nullable columns with no
-- default rewrite no rows.
ALTER TABLE discovery_finding_secret_moves
    ADD COLUMN IF NOT EXISTS residue_checked_at timestamptz,
    ADD COLUMN IF NOT EXISTS residue_run_id uuid;
