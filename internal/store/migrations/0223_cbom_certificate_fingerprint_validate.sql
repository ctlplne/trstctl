-- SPDX-License-Identifier: BUSL-1.1
-- Validate after the short metadata migration has committed.
ALTER TABLE crypto_assets VALIDATE CONSTRAINT crypto_assets_certificate_fingerprint_valid;
