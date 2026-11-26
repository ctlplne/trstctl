-- SPDX-License-Identifier: BUSL-1.1

-- A pre-upgrade member command may contain an event larger than the broker
-- accepts. Keep its admission fence, but let startup skip this exact command
-- and continue healing other tenants. A later bounded request can replace it.
ALTER TABLE tenant_member_upsert_commands
    ADD COLUMN recovery_blocked_reason text NOT NULL DEFAULT ''
    CHECK (recovery_blocked_reason IN ('', 'event_payload_too_large'));
ALTER TABLE tenant_member_offboard_commands
    ADD COLUMN recovery_blocked_reason text NOT NULL DEFAULT ''
    CHECK (recovery_blocked_reason IN ('', 'event_payload_too_large'));
