-- Subject-level privacy erasure (PRIVACY-001/002). The immutable event log keeps
-- append-only audit history; this read model records which tenant-bound subject
-- references have been erased and lets projections pseudonymize tenant tables on
-- replay without storing the raw subject in the erasure event.

ALTER TABLE tenant_members
    ADD COLUMN IF NOT EXISTS subject_ref text NOT NULL DEFAULT '';

ALTER TABLE api_tokens
    ADD COLUMN IF NOT EXISTS subject_ref text NOT NULL DEFAULT '';

CREATE TABLE privacy_subject_erasures (
    tenant_id        uuid NOT NULL,
    subject_ref      text NOT NULL,
    requested_by_ref text NOT NULL DEFAULT '',
    reason           text NOT NULL DEFAULT '',
    selectors        jsonb NOT NULL DEFAULT '{}',
    counts           jsonb NOT NULL DEFAULT '{}',
    erased_at        timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, subject_ref)
);

ALTER TABLE privacy_subject_erasures ENABLE ROW LEVEL SECURITY;
ALTER TABLE privacy_subject_erasures FORCE ROW LEVEL SECURITY;

CREATE POLICY privacy_subject_erasures_isolation ON privacy_subject_erasures
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX privacy_subject_erasures_erased_at_idx
    ON privacy_subject_erasures (tenant_id, erased_at DESC, subject_ref);

GRANT SELECT, INSERT, UPDATE, DELETE ON privacy_subject_erasures TO trstctl_app;
