-- AUD-41 / epic H3: immutable incident plan authority beside the H2 run.
-- Existing D6 rows remain legacy. New live/game-day rows carry a digest and
-- exact H1/H2 identities before the first trust-distribution outbox intent.
-- online-safe: PostgreSQL 14 stores these constant defaults in table metadata;
-- adding them does not rewrite the populated legacy projection.
ALTER TABLE incident_fleet_reissuance_runs
    ADD COLUMN migration_run_id text NOT NULL DEFAULT '',
    ADD COLUMN replacement_authority_id text NOT NULL DEFAULT '',
    ADD COLUMN mode text NOT NULL DEFAULT 'legacy',
    ADD COLUMN plan_digest text NOT NULL DEFAULT '',
    ADD COLUMN exact_trust_store_ids text[] NOT NULL DEFAULT '{}',
    ADD COLUMN exact_trust_hosts text[] NOT NULL DEFAULT '{}',
    ADD COLUMN candidate_trust_store_ids text[] NOT NULL DEFAULT '{}',
    ADD COLUMN candidate_trust_hosts text[] NOT NULL DEFAULT '{}';

ALTER TABLE incident_fleet_reissuance_runs
    ADD CONSTRAINT incident_fleet_reissuance_mode_chk
    CHECK (mode IN ('legacy', 'live', 'game_day')) NOT VALID;

ALTER TABLE incident_fleet_reissuance_runs
    VALIDATE CONSTRAINT incident_fleet_reissuance_mode_chk;

COMMENT ON COLUMN incident_fleet_reissuance_runs.plan_digest IS
    'Immutable digest of compromised/replacement authority, exact H1 scope, ordered H2 cohorts, and game-day boundary.';
