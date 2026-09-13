-- SPDX-License-Identifier: MPL-2.0
-- Record the route used by each successful channel. Older receipts remain
-- explicitly unknown; current routing configuration cannot reconstruct history.
ALTER TABLE notification_delivery_receipts
    ADD COLUMN routing_source text NOT NULL DEFAULT '',
    ADD COLUMN routing_policy_id text NOT NULL DEFAULT '',
    ADD COLUMN routing_policy_scope text NOT NULL DEFAULT '',
    ADD COLUMN routing_policy_digest text NOT NULL DEFAULT '';

CREATE INDEX notification_delivery_receipts_command_idx
    ON notification_delivery_receipts (tenant_id, destination, notification_key_digest);
