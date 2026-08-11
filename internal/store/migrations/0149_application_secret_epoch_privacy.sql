-- Application-secret command identities and pre-approval requester privacy.

-- Event identities must not collide with retained history after an offboarded
-- tenant UUID is registered again. This independent epoch is created lazily,
-- backed up with command receipts, and deleted by tenant offboarding.
CREATE TABLE application_secret_tenant_epochs (
    tenant_id  UUID        PRIMARY KEY,
    epoch_id   UUID        NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE application_secret_tenant_epochs ENABLE ROW LEVEL SECURITY;
ALTER TABLE application_secret_tenant_epochs FORCE ROW LEVEL SECURITY;

CREATE POLICY application_secret_tenant_epochs_isolation
    ON application_secret_tenant_epochs
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON application_secret_tenant_epochs TO trstctl_app;

COMMENT ON TABLE application_secret_tenant_epochs IS
    'Independent lifecycle epoch for deterministic application-secret event identities; offboarding deletes it so a re-registration cannot collide with retained old history.';

-- Before an exact approval request is durably bound, the crash-recovery fence
-- holds the requester as tenant ciphertext. requester_ref is a one-way privacy
-- selector that lets privacy.subject.erased delete that abandoned command without
-- opening every tenant ciphertext or retaining the erased subject.
ALTER TABLE application_secret_mutation_fences
    ADD COLUMN requester_ref CHAR(64),
    ADD CONSTRAINT application_secret_mutation_fences_requester_ref_chk
        CHECK (requester_ref IS NULL OR requester_ref ~ '^[0-9a-f]{64}$');
