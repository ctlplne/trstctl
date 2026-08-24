-- SPDX-License-Identifier: MPL-2.0
-- migrate: no-transaction

-- This migration runs outside a transaction because the final unique index is
-- built concurrently. Each preceding ALTER is independently atomic.

-- A routing policy can either be selected explicitly (manual) or apply to one
-- point in the operator hierarchy. Existing rows remain manual, so this
-- migration cannot silently change where an existing notification is sent.
ALTER TABLE notification_routing_policies
    ADD COLUMN scope_kind text NOT NULL DEFAULT 'manual',
    ADD COLUMN scope_ref text NOT NULL DEFAULT '';

ALTER TABLE notification_routing_policies
    ADD CONSTRAINT notification_routing_policies_scope_kind_check
    CHECK (scope_kind IN ('manual', 'global', 'workspace', 'owner', 'asset')),
    ADD CONSTRAINT notification_routing_policies_scope_ref_check
    CHECK (
        (scope_kind IN ('manual', 'global') AND scope_ref = '') OR
        (scope_kind = 'workspace' AND scope_ref IN (
            'certificate-lifecycle', 'machine-workload-trust', 'secrets-access',
            'software-trust', 'trust-operations'
        )) OR
        (scope_kind = 'owner' AND scope_ref LIKE 'owner/%' AND length(scope_ref) > 6) OR
        (scope_kind = 'asset' AND scope_ref LIKE '%/%' AND scope_ref NOT LIKE '%/')
    );

-- Only one effective rule may own a hierarchy point. Manual policies can still
-- coexist because operators select them by UUID.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS notification_routing_policies_effective_scope_uidx
    ON notification_routing_policies (tenant_id, scope_kind, scope_ref)
    WHERE scope_kind <> 'manual';
