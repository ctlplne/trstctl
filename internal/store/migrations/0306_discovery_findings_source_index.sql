-- SPDX-License-Identifier: BUSL-1.1
-- migrate: no-transaction
-- A105: the Posture dashboards read one source kind's findings (CT logs, drift)
-- a page at a time and count them on the server, so findings are reached by
-- their source as well as by id.
-- online-safe: CONCURRENTLY indexes the populated findings read model without blocking writes.
CREATE INDEX CONCURRENTLY IF NOT EXISTS discovery_findings_source_idx
    ON discovery_findings (tenant_id, source_id, id);
