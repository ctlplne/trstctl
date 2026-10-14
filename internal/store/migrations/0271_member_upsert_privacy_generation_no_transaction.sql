-- SPDX-License-Identifier: BUSL-1.1
-- migrate: no-transaction
-- A pending member upsert is bound to the erasure generation visible at claim.
-- NULL is the pre-erasure generation for existing pending commands; without a
-- retained source event, recovery refuses to publish one after an erasure.
ALTER TABLE tenant_member_upsert_commands
    ADD COLUMN IF NOT EXISTS privacy_erasure_event_id text;

-- Build the tenant/subject/sequence lookup without blocking privacy writes.
-- A retry clears an interrupted concurrent index before rebuilding it.
DROP INDEX CONCURRENTLY IF EXISTS privacy_subject_erasure_operations_subject_sequence_idx;
CREATE INDEX CONCURRENTLY privacy_subject_erasure_operations_subject_sequence_idx
    ON privacy_subject_erasure_operations (tenant_id, subject_ref, event_sequence DESC);
