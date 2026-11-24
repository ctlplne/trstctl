-- SPDX-License-Identifier: BUSL-1.1

-- Older source events can collide with the target uniqueness invariant after
-- they have entered JetStream. Keep their exact tenant and first sequence in
-- the durable quarantine marker while other tenants continue projecting.
ALTER TABLE projection_tenant_quarantines
    DROP CONSTRAINT projection_tenant_quarantines_reason_code_check;
ALTER TABLE projection_tenant_quarantines
    ADD CONSTRAINT projection_tenant_quarantines_reason_code_check
    CHECK (reason_code IN ('nul_text', 'invalid_utf8', 'workload_source_target_conflict'));
