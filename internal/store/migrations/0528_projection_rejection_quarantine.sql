-- SPDX-License-Identifier: BUSL-1.1

-- Record deterministic read-model data and integrity rejections by tenant so
-- replay can continue for unaffected tenants while the rejected one is fenced.
ALTER TABLE projection_tenant_quarantines
    DROP CONSTRAINT projection_tenant_quarantines_reason_code_check;
ALTER TABLE projection_tenant_quarantines
    ADD CONSTRAINT projection_tenant_quarantines_reason_code_check
    CHECK (reason_code IN ('nul_text', 'invalid_utf8', 'workload_source_target_conflict',
                          'json_unicode_escape', 'json_number_range',
                          'pcas_delegation_floor_out_of_range',
                          'discovery_finding_unprojectable', 'agent_heartbeat_invalid',
                          'native_failure_receipt_invalid', 'migration_approval_duplicate_start',
                          'attester_trust_source_referenced', 'secret_sync_trust_source_missing',
                          'migration_restore_inconsistent', 'projection_rejected'));
