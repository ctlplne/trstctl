-- A125/A196: the transit keyring, shared by every replica.
--
-- Each tenant's named transit keys are one sealed row: sealed through the tenant's key domain (the deployment KEK for a
-- tenant that has not migrated), never stored in the clear, and confined by RLS. revision is a compare-and-swap counter:
-- a replica saves only over the revision it last read, so two replicas creating or rotating keys at once cannot overwrite
-- each other, and a replica that misses a key reloads the row. Key bytes are deliberately not event-sourced; the event
-- log records the lifecycle facts.
CREATE TABLE IF NOT EXISTS transit_keyrings (
    tenant_id  uuid        PRIMARY KEY,
    sealed     bytea       NOT NULL,
    revision   bigint      NOT NULL CHECK (revision > 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE transit_keyrings ENABLE ROW LEVEL SECURITY;
ALTER TABLE transit_keyrings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS transit_keyrings_isolation ON transit_keyrings;
CREATE POLICY transit_keyrings_isolation ON transit_keyrings
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON transit_keyrings TO trstctl_app;
