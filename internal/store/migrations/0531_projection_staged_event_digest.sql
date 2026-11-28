-- SPDX-License-Identifier: BUSL-1.1

-- A staged core projection carries the exact event digest in the same
-- transaction as its read-model write. Existing receipts remain valid for
-- their original family and have no staged digest.
ALTER TABLE projection_applied_event_receipts
    ADD COLUMN stage_digest BYTEA,
    ADD CONSTRAINT projection_applied_event_stage_digest_check
        CHECK (stage_digest IS NULL OR octet_length(stage_digest) = 32);
