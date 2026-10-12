-- The immutable breakglass.issued event owns the signed public bundle. This
-- tenant-scoped projection makes an interrupted response recoverable by an
-- operator without scanning event history on a request path.
CREATE TABLE breakglass_issue_receipts (
    tenant_id UUID NOT NULL,
    ceremony_id UUID NOT NULL,
    request_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    bundle JSONB NOT NULL,
    event_sequence BIGINT NOT NULL CHECK (event_sequence > 0),
    issued_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, ceremony_id),
    CHECK (request_id <> ''),
    CHECK (subject <> ''),
    CHECK (request_digest <> ''),
    CHECK (jsonb_typeof(bundle) = 'object')
);
CREATE INDEX breakglass_issue_receipts_recent_idx
    ON breakglass_issue_receipts (tenant_id, event_sequence DESC);

ALTER TABLE breakglass_issue_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE breakglass_issue_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY breakglass_issue_receipts_isolation ON breakglass_issue_receipts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON breakglass_issue_receipts TO trstctl_app;

-- Warm upgrades inspect only the indexed breakglass.issued subjects through a
-- finite source cut. NULL means never scanned (including N-1 rows); the
-- cursor advances after the full pass succeeds. Leaving NULL avoids altering
-- the value of an existing checkpoint during a schema-only migration.
ALTER TABLE projection_checkpoint ADD COLUMN breakglass_issue_checked_through BIGINT
    CHECK (breakglass_issue_checked_through >= 0);
