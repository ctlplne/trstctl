-- migrate: no-transaction
-- SPDX-License-Identifier: BUSL-1.1

-- AUD-46: each relay page resolves only the owner names it carries. This
-- expression index makes that bounded lookup independent of the total owner
-- estate size. CONCURRENTLY avoids blocking writes to the populated owners
-- table while an existing deployment upgrades.
CREATE INDEX CONCURRENTLY IF NOT EXISTS owners_cmdb_name_idx
    ON owners (tenant_id, lower(btrim(name)), id);
