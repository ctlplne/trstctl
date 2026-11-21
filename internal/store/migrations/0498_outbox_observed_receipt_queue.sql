-- SPDX-License-Identifier: BUSL-1.1
-- migrate: no-transaction
-- Source receipts stage already-performed effects until the orchestrator
-- records delivery. The leader scans this sparse queue once per second, so a
-- large delivered-outbox history must not turn each sweep into a table scan.
CREATE INDEX CONCURRENTLY IF NOT EXISTS outbox_observed_receipt_queue_idx
    ON outbox (id)
    WHERE status = 'receipt_observed'
      AND claimed_by_agent_id IS NULL
      AND delivered_at IS NULL;
