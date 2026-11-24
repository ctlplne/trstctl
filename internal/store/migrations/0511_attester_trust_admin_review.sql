-- CR-195: pre-upgrade trust sources could be written by issuance-only tokens.
-- Keep their public configuration visible, but require an issuer administrator
-- to reapprove it before any verifier can use it. New v2 upsert events clear
-- this flag only after the issuer-administration route check.
ALTER TABLE workload_attester_trust_sources
    ADD COLUMN admin_review_required boolean NOT NULL DEFAULT true;

-- Pending command recovery must reproduce the exact event version. Existing
-- command rows were written as v1; new issuer-admin upserts use v2.
ALTER TABLE workload_attester_trust_commands
    ADD COLUMN event_schema_version integer NOT NULL DEFAULT 1
    CHECK (event_schema_version IN (1, 2));
