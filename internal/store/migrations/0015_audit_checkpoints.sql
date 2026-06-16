-- Audit retention checkpoints (R4.4). Each row seals a boundary at which a
-- tenant's audit records up to boundary_seq were archived to cold storage (a
-- signed, offline-verifiable bundle at archive_uri) and pruned from the hot event
-- log. boundary_hash is the audit chain head at the boundary — the seed that keeps
-- the surviving suffix verifiable across the prune, so VerifyChain still holds.
-- Per AN-1 every row carries tenant_id and is confined by row-level security; a
-- checkpoint is per tenant, and a tenant may seal many over time.
CREATE TABLE audit_checkpoints (
    tenant_id     uuid        NOT NULL,
    boundary_seq  bigint      NOT NULL,
    boundary_hash text        NOT NULL,
    record_count  bigint      NOT NULL DEFAULT 0,
    archive_uri   text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, boundary_seq)
);
ALTER TABLE audit_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_checkpoints_isolation ON audit_checkpoints
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_checkpoints TO trstctl_app;
