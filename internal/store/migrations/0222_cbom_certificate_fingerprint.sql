-- SPDX-License-Identifier: BUSL-1.1
-- Historical observations have no retained leaf identity. Keep them unknown;
-- never backfill a fingerprint by joining hostname or algorithm labels.
ALTER TABLE crypto_assets ADD COLUMN certificate_fingerprint text NOT NULL DEFAULT '';
ALTER TABLE crypto_assets ADD CONSTRAINT crypto_assets_certificate_fingerprint_valid
    CHECK (certificate_fingerprint = '' OR
           (kind = 'certificate-key' AND certificate_fingerprint ~ '^[0-9a-f]{64}$')) NOT VALID;
