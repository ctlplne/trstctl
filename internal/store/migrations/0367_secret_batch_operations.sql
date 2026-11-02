-- A236: environment promotion and folder restore reuse the batch-import
-- reservation. A pending batch names its operation so crash recovery appends
-- the right event, and every projection checks it executes its own command.
ALTER TABLE application_secret_import_batches
    ADD COLUMN operation TEXT NOT NULL DEFAULT 'import'
    CHECK (operation IN ('import', 'promotion', 'restore'));
