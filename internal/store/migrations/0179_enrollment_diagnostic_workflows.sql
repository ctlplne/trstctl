-- AUD-49: preserve the exact failed operation and its prove-fixed target.
--
-- Older rows collapsed every tenant's failures by protocol/step/cause. That
-- made two unrelated devices with the same failure indistinguishable. The
-- immutable v1 events remain replayable under a deterministic legacy id; v2
-- events carry an id derived from the exact operation/identity/endpoint refs.
ALTER TABLE enrollment_diagnostic_observations
    ADD COLUMN diagnostic_id text;

UPDATE enrollment_diagnostic_observations
   SET diagnostic_id = 'legacy:' || protocol || ':' || step || ':' || cause
 WHERE tenant_id IS NOT NULL
   AND diagnostic_id IS NULL;

ALTER TABLE enrollment_diagnostic_observations
    ALTER COLUMN diagnostic_id SET NOT NULL;

ALTER TABLE enrollment_diagnostics
    ADD COLUMN diagnostic_id text,
    ADD COLUMN operation_ref text NOT NULL DEFAULT '',
    ADD COLUMN identity_ref text NOT NULL DEFAULT '',
    ADD COLUMN endpoint_ref text NOT NULL DEFAULT '',
    ADD COLUMN verification_kind text NOT NULL DEFAULT '',
    ADD COLUMN verification_address text NOT NULL DEFAULT '',
    ADD COLUMN verification_server_name text NOT NULL DEFAULT '',
    ADD COLUMN expected_fingerprint text NOT NULL DEFAULT '',
    ADD COLUMN verification_endpoint_id text NOT NULL DEFAULT '',
    ADD COLUMN verification_queued_at timestamptz,
    ADD COLUMN verification_event_sequence bigint NOT NULL DEFAULT 0;

UPDATE enrollment_diagnostics
   SET diagnostic_id = 'legacy:' || protocol || ':' || step || ':' || cause
 WHERE tenant_id IS NOT NULL
   AND diagnostic_id IS NULL;

ALTER TABLE enrollment_diagnostics
    ALTER COLUMN diagnostic_id SET NOT NULL;

-- Migration 0187 builds the populated observation lookup and replacement
-- diagnostic key online. Migration 0188 then performs only the short
-- catalog swap from the legacy class key to the already-validated exact key.

COMMENT ON COLUMN enrollment_diagnostics.diagnostic_id IS
    'Stable tenant-local id for one exact failed operation; v1 replay uses a legacy class id.';
