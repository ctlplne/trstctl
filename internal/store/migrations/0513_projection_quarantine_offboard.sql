-- SPDX-License-Identifier: BUSL-1.1

-- Offboarding must erase the quarantined tenant's operational denial row with
-- every other tenant-owned row. Its RLS policy still confines this grant to
-- the current tenant_id transaction scope.
GRANT DELETE ON projection_tenant_quarantines TO trstctl_app;
