-- AUD-105/AUD-114: privacy history rewrites may sanitize immutable event bytes
-- only when every independent PostgreSQL recovery receiver carries the exact
-- erasure authority and closed disposition. Legacy rows remain version 0 and
-- ambiguous queued code-signing rows remain non-dispatchable; this migration
-- never invents authority that old releases did not persist.

ALTER TABLE application_secret_mutation_fences
    ADD COLUMN privacy_rewrite_version SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN privacy_subject_ref CHAR(64),
    ADD COLUMN privacy_erasure_operation_id TEXT,
    ADD COLUMN privacy_erasure_event_id TEXT,
    ADD COLUMN privacy_disposition TEXT NOT NULL DEFAULT 'none';

ALTER TABLE application_secret_mutation_fences
    ADD CONSTRAINT application_secret_fence_privacy_stamp_complete CHECK (
        (privacy_rewrite_version = 0
         AND privacy_subject_ref IS NULL
         AND privacy_erasure_operation_id IS NULL
         AND privacy_erasure_event_id IS NULL
         AND privacy_disposition = 'none')
        OR
        (privacy_rewrite_version = 1
         AND privacy_subject_ref ~ '^[0-9a-f]{64}$'
         AND privacy_erasure_operation_id ~ '^sha256:[0-9a-f]{64}$'
         AND privacy_erasure_event_id ~ '^sha256:[0-9a-f]{64}$'
         AND privacy_disposition IN ('name_tombstoned', 'sync_erased', 'approval_sanitized'))
    ) NOT VALID;
ALTER TABLE application_secret_mutation_fences
    VALIDATE CONSTRAINT application_secret_fence_privacy_stamp_complete;

ALTER TABLE approved_target_event_fences
    ADD COLUMN semantic_version SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN privacy_rewrite_version SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN privacy_subject_ref CHAR(64),
    ADD COLUMN privacy_erasure_operation_id TEXT,
    ADD COLUMN privacy_erasure_event_id TEXT,
    ADD COLUMN privacy_disposition TEXT NOT NULL DEFAULT 'none';

ALTER TABLE approved_target_event_fences
    ADD CONSTRAINT approved_target_fence_semantic_version_chk
        CHECK (semantic_version IN (1, 2)) NOT VALID,
    ADD CONSTRAINT approved_target_fence_privacy_stamp_complete CHECK (
        (privacy_rewrite_version = 0
         AND privacy_subject_ref IS NULL
         AND privacy_erasure_operation_id IS NULL
         AND privacy_erasure_event_id IS NULL
         AND privacy_disposition = 'none')
        OR
        (privacy_rewrite_version = 1
         AND privacy_subject_ref ~ '^[0-9a-f]{64}$'
         AND privacy_erasure_operation_id ~ '^sha256:[0-9a-f]{64}$'
         AND privacy_erasure_event_id ~ '^sha256:[0-9a-f]{64}$'
         AND privacy_disposition = 'pseudonymized')
    ) NOT VALID;
ALTER TABLE approved_target_event_fences
    VALIDATE CONSTRAINT approved_target_fence_semantic_version_chk;
ALTER TABLE approved_target_event_fences
    VALIDATE CONSTRAINT approved_target_fence_privacy_stamp_complete;

ALTER TABLE application_secret_mutation_receipts
    ADD COLUMN semantic_version SMALLINT NOT NULL DEFAULT 1;
ALTER TABLE application_secret_mutation_receipts
    ADD CONSTRAINT application_secret_receipt_semantic_version_chk
        CHECK (semantic_version IN (1, 2)) NOT VALID;
ALTER TABLE application_secret_mutation_receipts
    VALIDATE CONSTRAINT application_secret_receipt_semantic_version_chk;

ALTER TABLE code_signing_operations
    ADD COLUMN approval_authority_version SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN approval_resource_kind TEXT,
    ADD COLUMN approval_resource_id TEXT,
    ADD COLUMN approval_action TEXT,
    ADD COLUMN approval_target_version BIGINT,
    ADD COLUMN privacy_rewrite_version SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN privacy_subject_ref CHAR(64),
    ADD COLUMN privacy_erasure_operation_id TEXT,
    ADD COLUMN privacy_erasure_event_id TEXT,
    ADD COLUMN privacy_disposition TEXT NOT NULL DEFAULT 'none';

ALTER TABLE code_signing_operations
    ADD CONSTRAINT code_signing_approval_authority_complete CHECK (
        (approval_authority_version = 0
         AND approval_resource_kind IS NULL
         AND approval_resource_id IS NULL
         AND approval_action IS NULL
         AND approval_target_version IS NULL)
        OR
        (approval_authority_version = 1
         AND source_event_id IS NOT NULL
         AND approval_request_id IS NOT NULL
         AND approval_intent_digest ~ '^sha256:[0-9a-f]{64}$'
         AND command_semantic_sha256 ~ '^[0-9a-f]{64}$'
         AND approval_resource_kind = 'code_signing'
         AND length(btrim(approval_resource_id)) > 0
         AND approval_action = 'sign'
         AND approval_target_version = 0)
    ) NOT VALID,
    ADD CONSTRAINT code_signing_privacy_stamp_complete CHECK (
        (privacy_rewrite_version = 0
         AND privacy_subject_ref IS NULL
         AND privacy_erasure_operation_id IS NULL
         AND privacy_erasure_event_id IS NULL
         AND privacy_disposition = 'none')
        OR
        (privacy_rewrite_version = 1
         AND approval_authority_version = 1
         AND privacy_subject_ref ~ '^[0-9a-f]{64}$'
         AND privacy_erasure_operation_id ~ '^sha256:[0-9a-f]{64}$'
         AND privacy_erasure_event_id ~ '^sha256:[0-9a-f]{64}$'
         AND privacy_disposition = 'approval_sanitized')
    ) NOT VALID;
ALTER TABLE code_signing_operations
    VALIDATE CONSTRAINT code_signing_approval_authority_complete;
ALTER TABLE code_signing_operations
    VALIDATE CONSTRAINT code_signing_privacy_stamp_complete;

COMMENT ON COLUMN application_secret_mutation_fences.privacy_erasure_operation_id IS
    'Exact deterministic privacy erasure operation that authorized the closed fence disposition; NULL means no privacy rewrite.';
COMMENT ON COLUMN approved_target_event_fences.semantic_version IS
    'Version 1 is the historical actor-sensitive digest; version 2 preserves actor role shape while allowing only typed privacy spelling changes.';
COMMENT ON COLUMN code_signing_operations.approval_authority_version IS
    'Version 0 is legacy/unknown and must fail worker dispatch for an approved queued command; version 1 carries the complete immutable target authority.';
