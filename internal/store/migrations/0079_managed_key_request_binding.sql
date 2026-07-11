-- SPDX-License-Identifier: MPL-2.0
-- Keep the authenticated managed-key command binding after the general HTTP
-- idempotency response cache is retention-GC'd. Only the non-secret SHA-256
-- digest is stored; no principal name or credential material enters this row.

ALTER TABLE managed_key_operations
    ADD COLUMN IF NOT EXISTS request_binding text NOT NULL DEFAULT '';
