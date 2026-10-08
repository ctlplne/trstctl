-- SPDX-License-Identifier: BUSL-1.1
-- Cloud KMS accepted deletion is not proof that provider-held key bytes are gone.
-- Historical zeroized rows are left untouched because their immutable v2 event
-- records that claim; the public API presents those rows conservatively.

ALTER TABLE managed_keys ADD CONSTRAINT managed_keys_state_v2_check
    CHECK (state IN ('active', 'superseded', 'revoked', 'zeroized', 'deletion_pending')) NOT VALID;
ALTER TABLE managed_keys VALIDATE CONSTRAINT managed_keys_state_v2_check;
ALTER TABLE managed_keys DROP CONSTRAINT managed_keys_state_check;
ALTER TABLE managed_keys RENAME CONSTRAINT managed_keys_state_v2_check TO managed_keys_state_check;
