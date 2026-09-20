-- SPDX-License-Identifier: BUSL-1.1

-- Rows projected before ordered lifecycle replay may contain a predecessor
-- fingerprint that the corresponding v0.5.x event omitted. Mark exactly those
-- rows so the new projector can treat the absent historical field as unknown
-- without weakening binding checks for any command created after this upgrade.
ALTER TABLE lifecycle_rotation_runs
    ADD COLUMN legacy_predecessor_binding boolean NOT NULL DEFAULT true;

ALTER TABLE lifecycle_rotation_runs
    ALTER COLUMN legacy_predecessor_binding SET DEFAULT false;
