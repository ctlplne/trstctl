-- SPDX-License-Identifier: BUSL-1.1
-- The watch's requested_by becomes "scheduler" on a daily round. Keep the
-- human or API-token subject that granted private egress separately, so each
-- scheduled or pending probe can check current standing authority. Historical
-- private grants start unattributed and fail closed until reauthorized.
ALTER TABLE switching_imports
    ADD COLUMN watch_grant_by text NOT NULL DEFAULT '';
