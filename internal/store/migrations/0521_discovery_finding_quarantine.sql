-- SPDX-License-Identifier: BUSL-1.1

-- Older producers could append an observation whose indexed natural key or
-- metadata exceeded the projector's safe bounds. Confine that legacy event to
-- its tenant so healthy tenants continue projecting.
ALTER TABLE projection_tenant_quarantines
    DROP CONSTRAINT projection_tenant_quarantines_reason_code_check;
ALTER TABLE projection_tenant_quarantines
    ADD CONSTRAINT projection_tenant_quarantines_reason_code_check
    CHECK (reason_code IN ('nul_text', 'invalid_utf8', 'workload_source_target_conflict',
                          'json_unicode_escape', 'json_number_range',
                          'pcas_delegation_floor_out_of_range',
                          'discovery_finding_unprojectable'));
