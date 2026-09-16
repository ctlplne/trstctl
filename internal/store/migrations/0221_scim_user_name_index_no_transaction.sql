-- SPDX-License-Identifier: MPL-2.0
-- migrate: no-transaction
-- Keep membership writes available while the unique alias index is built.
-- An interrupted concurrent build can leave an invalid index. Rebuild it on
-- retry before the migration runner records the completed, valid index.
DROP INDEX CONCURRENTLY IF EXISTS tenant_members_scim_user_name_idx;
CREATE UNIQUE INDEX CONCURRENTLY tenant_members_scim_user_name_idx
    ON tenant_members (tenant_id, lower(scim_identity->>'user_name'))
    WHERE scim_identity IS NOT NULL;
ALTER TABLE tenant_members VALIDATE CONSTRAINT tenant_members_scim_identity_object;
