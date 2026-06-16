-- Tenant offboarding / right-to-erasure (TENANT-002). A tenant deletion erases
-- every tenant-scoped row, and OffboardTenant does it entirely under row-level
-- security (Store.WithTenant): each DELETE is confined to the offboarded tenant
-- by the same USING (tenant_id = GUC) policy that confines a read, so it is
-- safe by construction — it can never reach another tenant's rows (AN-1).
--
-- Three operational/system tables (idempotency_keys, outbox, rate_limits) were
-- granted only SELECT/INSERT/UPDATE to the RLS-subject role, because nothing
-- previously deleted from them under a tenant context (the idempotency GC sweep
-- runs as the privileged role). Offboarding does delete from them, scoped to the
-- tenant, so grant DELETE to trstctl_app here. They keep their FORCE-d
-- USING (tenant_id = GUC) policy, so a DELETE under WithTenant still removes only
-- the current tenant's rows.
GRANT DELETE ON idempotency_keys TO trstctl_app;
GRANT DELETE ON outbox           TO trstctl_app;
GRANT DELETE ON rate_limits      TO trstctl_app;
