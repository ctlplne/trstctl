-- SPDX-License-Identifier: BUSL-1.1

-- Historical JSON events may contain an unpaired surrogate or a numeric value
-- outside PostgreSQL jsonb's range. Quarantine only that tenant while replay
-- continues for others; new events are rejected before append.
ALTER TABLE projection_tenant_quarantines
    DROP CONSTRAINT projection_tenant_quarantines_reason_code_check;
ALTER TABLE projection_tenant_quarantines
    ADD CONSTRAINT projection_tenant_quarantines_reason_code_check
    CHECK (reason_code IN ('nul_text', 'invalid_utf8', 'workload_source_target_conflict',
                          'json_unicode_escape', 'json_number_range'));
