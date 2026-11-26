-- SPDX-License-Identifier: BUSL-1.1

-- An older signer may already have sealed a delegation floor above PostgreSQL
-- bigint. Preserve the exact event, quarantine its tenant, and let other
-- tenants' projections advance instead of failing the global cursor.
ALTER TABLE projection_tenant_quarantines
    DROP CONSTRAINT projection_tenant_quarantines_reason_code_check;
ALTER TABLE projection_tenant_quarantines
    ADD CONSTRAINT projection_tenant_quarantines_reason_code_check
    CHECK (reason_code IN ('nul_text', 'invalid_utf8', 'workload_source_target_conflict',
                          'json_unicode_escape', 'json_number_range',
                          'pcas_delegation_floor_out_of_range'));
