-- SPDX-License-Identifier: BUSL-1.1

-- Routing policy IDs identify a policy within its tenant. Replace the
-- deployment-wide primary key and its redundant tenant-unique constraint with
-- one tenant-scoped primary key in a single atomic schema change.
ALTER TABLE notification_routing_policies
    DROP CONSTRAINT notification_routing_policies_pkey,
    DROP CONSTRAINT notification_routing_policies_tenant_id_id_key,
    ADD CONSTRAINT notification_routing_policies_pkey PRIMARY KEY (tenant_id, id);
