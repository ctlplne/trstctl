-- migrate: no-transaction
-- AUD-148: finish index work deferred by transactional data migrations without
-- blocking live writers while PostgreSQL scans populated command/read tables.
-- Every statement is independently retry-safe before schema_migrations records
-- this no-transaction migration.

DROP INDEX CONCURRENTLY IF EXISTS application_secret_mutation_fences_actor_subject_ref_idx;
CREATE INDEX CONCURRENTLY application_secret_mutation_fences_actor_subject_ref_idx
    ON application_secret_mutation_fences (tenant_id, actor_subject_ref)
    WHERE actor_subject_ref IS NOT NULL;

DROP INDEX CONCURRENTLY IF EXISTS dynamic_secret_leases_epoch_idempotency_idx;
CREATE INDEX CONCURRENTLY dynamic_secret_leases_epoch_idempotency_idx
    ON dynamic_secret_leases (tenant_id, tenant_epoch, idempotency_key);

DROP INDEX CONCURRENTLY IF EXISTS dynamic_secret_operations_epoch_idempotency_idx;
CREATE INDEX CONCURRENTLY dynamic_secret_operations_epoch_idempotency_idx
    ON dynamic_secret_operations (tenant_id, tenant_epoch, idempotency_key);

DROP INDEX CONCURRENTLY IF EXISTS secret_rotation_schedule_commands_registration_claim_idx;
CREATE INDEX CONCURRENTLY secret_rotation_schedule_commands_registration_claim_idx
    ON secret_rotation_schedule_commands (
        tenant_id, tenant_registration_event_sequence,
        status, lease_until, due_at, schedule_id
    );

DROP INDEX CONCURRENTLY IF EXISTS enrollment_diagnostic_observations_diagnostic_idx;
CREATE INDEX CONCURRENTLY enrollment_diagnostic_observations_diagnostic_idx
    ON enrollment_diagnostic_observations (tenant_id, diagnostic_id, event_sequence DESC);

DROP INDEX CONCURRENTLY IF EXISTS enrollment_diagnostics_tenant_diagnostic_id_uq;
CREATE UNIQUE INDEX CONCURRENTLY enrollment_diagnostics_tenant_diagnostic_id_uq
    ON enrollment_diagnostics (tenant_id, diagnostic_id);
