-- Event-projected, tenant-scoped public trust paths for offline-root succession.
-- A ceremony is the immutable key; receipt, lineage and completion project in
-- the same transaction, including during a cold replay.
CREATE TABLE ca_offline_rekey_receipts (
    tenant_id UUID NOT NULL,
    ceremony_id UUID NOT NULL,
    predecessor_authority_id UUID NOT NULL,
    successor_authority_id UUID NOT NULL,
    new_signed_by_previous_der BYTEA NOT NULL,
    previous_signed_by_new_der BYTEA NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, ceremony_id),
    CHECK (predecessor_authority_id <> successor_authority_id),
    CHECK (octet_length(new_signed_by_previous_der) > 0),
    CHECK (octet_length(previous_signed_by_new_der) > 0)
);

ALTER TABLE ca_offline_rekey_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ca_offline_rekey_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY ca_offline_rekey_receipts_isolation ON ca_offline_rekey_receipts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON ca_offline_rekey_receipts TO trstctl_app;
