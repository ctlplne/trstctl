-- SPDX-License-Identifier: BUSL-1.1

-- AUD-65 binds an owner action to the exact production graph-readiness row the
-- operator saw. The campaign/finding tables remain projections of immutable
-- pqc.migration_campaign.* events; this digest is evidence, not a new topology
-- source of truth. NULL preserves legacy, manually created rows without writing
-- synthetic values across the live table; current projections always insert an
-- explicit empty string or bound digest.
ALTER TABLE pqc_migration_campaign_findings
    ADD COLUMN readiness_digest TEXT;

ALTER TABLE pqc_migration_campaign_findings
    ADD CONSTRAINT pqc_migration_campaign_findings_readiness_digest_chk
    CHECK (readiness_digest IS NULL OR readiness_digest = '' OR readiness_digest ~ '^sha256:[0-9a-f]{64}$');
