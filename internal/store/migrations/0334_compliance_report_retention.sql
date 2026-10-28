-- A206: a person can hold a completed report run's signed report, and the
-- opt-in report retention removes reports older than its window unless held.
-- Both are projections of the compliance.report_run.legal_hold_* and
-- compliance.report_run.artifact_expir* events, sequenced apart from the run's
-- own lifecycle events. artifact_expiry_requested_at marks a removal the
-- retention has queued, so the next sweep does not queue it again; a hold
-- clears it. 0335 indexes the retention's listing.
ALTER TABLE compliance_report_runs
    ADD COLUMN IF NOT EXISTS legal_hold_reason text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS legal_hold_by text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS legal_hold_at timestamptz,
    ADD COLUMN IF NOT EXISTS artifact_expiry_requested_at timestamptz,
    ADD COLUMN IF NOT EXISTS artifact_expired_at timestamptz,
    ADD COLUMN IF NOT EXISTS retention_event_sequence bigint NOT NULL DEFAULT 0
        CHECK (retention_event_sequence >= 0);
