-- P12-L1: a factory batch can pin the roots its devices attest their own keys
-- against at birth; each birth certificate records its attestation (verified,
-- missing or refused) and the batch counts the births without a verified one.
-- Empty and zero for every existing batch and birth, which keep enrolling as
-- before. Online-safe: adding columns with constant defaults rewrites no rows.
ALTER TABLE factory_batches
    ADD COLUMN IF NOT EXISTS device_attestation_roots text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS unattested integer NOT NULL DEFAULT 0;
ALTER TABLE factory_birth_certificates
    ADD COLUMN IF NOT EXISTS attestation text NOT NULL DEFAULT '';
