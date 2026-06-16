-- Tenants RLS symmetry (ARCH-009): the tenants_isolation policy was created in
-- 0001_init.sql with only a USING clause (read/visibility filter) and NO WITH
-- CHECK clause (write filter), unlike every domain table in 0004, which has both.
-- A USING-only policy lets a session whose tenant GUC is set to tenant A write a
-- row for tenant B (the write is not checked against the GUC) — there is no
-- demonstrated cross-tenant write today (tenant_id is the PK and the read model
-- writes tenants via the system pool, RLS-bypassing), but for AN-1 completeness the
-- policy must constrain writes as well as reads.
--
-- ALTER POLICY cannot ADD a WITH CHECK clause to an existing policy, so we replace
-- the policy: drop the USING-only one and recreate it with BOTH USING and WITH
-- CHECK keyed on the same trstctl.tenant_id GUC (unset GUC => NULL => deny, fail
-- closed), matching the domain tables.
--
-- This is an additive, idempotent forward migration: DROP POLICY IF EXISTS makes it
-- re-runnable, and the recreated policy is behaviorally identical for reads while
-- adding the missing write check. Existing rows are unaffected; the system pool
-- (table owner) still bypasses RLS for projection writes.

DROP POLICY IF EXISTS tenants_isolation ON tenants;

CREATE POLICY tenants_isolation ON tenants
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
