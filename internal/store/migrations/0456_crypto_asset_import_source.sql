-- X6-L3: a CBOM import retires what a newer BOM of its source drops. Each
-- imported fact records the import source that last observed it, so an
-- import's reconciliation (cbom.import.reconciled) retires exactly its own
-- source's earlier facts. Projected from cbom.asset.observed. Rows recorded
-- before this name no source ('') and keep their content; trstctl's own
-- scans name none. A column with a constant default rewrites no rows.
ALTER TABLE crypto_assets
    ADD COLUMN IF NOT EXISTS import_source text NOT NULL DEFAULT '';
