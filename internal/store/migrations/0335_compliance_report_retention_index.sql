-- SPDX-License-Identifier: BUSL-1.1
-- migrate: no-transaction
-- A206: the report retention lists a tenant's completed runs past the window
-- that are not held, have no removal queued and still have their report.
-- online-safe: CONCURRENTLY indexes the populated report-run read model without blocking writes.
CREATE INDEX CONCURRENTLY IF NOT EXISTS compliance_report_runs_retention_idx
    ON compliance_report_runs (tenant_id, completed_at)
    WHERE status = 'completed' AND legal_hold_at IS NULL
      AND artifact_expiry_requested_at IS NULL AND artifact_expired_at IS NULL;
