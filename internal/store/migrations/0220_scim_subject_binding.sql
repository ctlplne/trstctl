-- SPDX-License-Identifier: BUSL-1.1
-- Preserve provisioning identifiers independently of the authenticated subject.
-- Legacy rows are unbound until explicitly provisioned with the new contract.
ALTER TABLE tenant_members ADD COLUMN scim_identity jsonb;
ALTER TABLE tenant_members ADD CONSTRAINT tenant_members_scim_identity_object
    CHECK (scim_identity IS NULL OR jsonb_typeof(scim_identity) = 'object') NOT VALID;
-- Validate existing rows and build the unique index outside this short expansion
-- transaction in 0221, so scanning a populated membership table does not hold
-- the expansion's exclusive table lock.
