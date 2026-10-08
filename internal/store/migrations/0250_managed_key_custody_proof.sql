-- SPDX-License-Identifier: BUSL-1.1
-- A lifecycle event remains historical. A separate projection records the last
-- provider signature proof, which may become stale after any provider restart.
ALTER TABLE managed_key_operations DROP CONSTRAINT managed_key_operations_action_check;
ALTER TABLE managed_key_operations ADD CONSTRAINT managed_key_operations_action_check
    CHECK (action IN ('generate', 'rotate', 'revoke', 'zeroize', 'verify_custody'));

ALTER TABLE managed_keys
    ADD COLUMN custody_status TEXT NOT NULL DEFAULT 'not_checked'
        CHECK (custody_status IN ('not_checked', 'pending', 'verified', 'unavailable')),
    ADD COLUMN custody_checked_at TIMESTAMPTZ;
