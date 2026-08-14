-- Exact authenticated actor custody for crash-recoverable application-secret commands.
--
-- A command may crash before Append or after Append but before SQL projection.
-- Persisting the actor beside the sealed command lets restart reproduce and verify
-- the same event envelope instead of losing attribution or accepting actor drift.
-- actor_subject_ref is the one-way tenant-bound privacy selector; erasure clears it
-- after replacing only actor.subject with the deterministic placeholder.
ALTER TABLE application_secret_mutation_fences
    ADD COLUMN actor JSONB,
    ADD COLUMN actor_subject_ref CHAR(64),
    ADD CONSTRAINT application_secret_mutation_fences_actor_shape_chk CHECK (
        actor IS NULL OR (
            jsonb_typeof(actor) = 'object'
            AND actor ? 'subject'
            AND jsonb_typeof(actor->'subject') = 'string'
            AND length(btrim(actor->>'subject')) > 0
            AND (NOT actor ? 'roles' OR jsonb_typeof(actor->'roles') = 'array')
        )
    ),
    ADD CONSTRAINT application_secret_mutation_fences_actor_ref_chk CHECK (
        actor_subject_ref IS NULL OR actor_subject_ref ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT application_secret_mutation_fences_actor_ref_shape_chk CHECK (
        actor IS NOT NULL OR actor_subject_ref IS NULL
    );

-- Migration 0187 builds the populated-table selector index online. Keeping it
-- here would hold application-secret writers behind a table-wide index build.

COMMENT ON COLUMN application_secret_mutation_fences.actor IS
    'Exact authenticated event actor persisted across pre/post-Append crash recovery; privacy erasure rewrites only subject and preserves roles.';

COMMENT ON COLUMN application_secret_mutation_fences.actor_subject_ref IS
    'Tenant-bound one-way selector for actor privacy erasure; NULL after erasure or for legacy/system-unattributed fences.';
