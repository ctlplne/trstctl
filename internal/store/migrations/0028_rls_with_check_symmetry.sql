-- RLS WITH CHECK symmetry (TENANT-008): two domain tables created their
-- isolation policy with only a USING clause (the read/visibility filter) and no
-- WITH CHECK clause (the write filter):
--
--   * credentials            (0014_credentials.sql)
--   * certificate_profiles   (0016_certificate_profiles.sql)
--
-- This is SAFE today — PostgreSQL re-uses the USING expression as the implicit
-- WITH CHECK for INSERT/UPDATE when no explicit WITH CHECK is given, so a
-- cross-tenant write is already blocked (verified by a live two-tenant probe:
-- INSERT under tenant A for tenant B fails with SQLSTATE 42501). But it is
-- INCONSISTENT with the other domain tables (0004) and with the tenants table
-- (made symmetric in 0025_tenants_rls_with_check.sql), and the asymmetry is a
-- future-proofing hazard: if someone later broadens USING (e.g. to expose shared
-- rows for reads) the now-implicit write check would silently widen too.
--
-- For AN-1 completeness we make these two policies explicit, exactly mirroring
-- 0025: ALTER POLICY cannot ADD a WITH CHECK clause, so we DROP and recreate each
-- policy with BOTH USING and WITH CHECK keyed on the same trstctl.tenant_id GUC
-- (unset GUC => NULL => deny, fail closed). This is behaviorally identical for
-- both reads and writes — it only makes the already-effective write filter
-- explicit — so it is a pure consistency lock, not a behavior change.
--
-- Additive and idempotent: DROP POLICY IF EXISTS makes it re-runnable; existing
-- rows are unaffected; the system pool (table owner) still bypasses RLS for
-- projection writes. After this migration pg_policies shows ZERO USING-only
-- isolation policies across the tenant tables (the TENANT-008 acceptance).

DROP POLICY IF EXISTS credentials_isolation ON credentials;

CREATE POLICY credentials_isolation ON credentials
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

DROP POLICY IF EXISTS certificate_profiles_isolation ON certificate_profiles;

CREATE POLICY certificate_profiles_isolation ON certificate_profiles
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
