-- A208: the report retention leaves a report the archive's S3 Object Lock
-- still protects (a retention not yet expired, or a legal hold). The removal
-- records until when it was deferred, and the retention's sweep skips the run
-- until then. A projection of compliance.report_run.artifact_expiry_deferred.
ALTER TABLE compliance_report_runs
    ADD COLUMN IF NOT EXISTS artifact_storage_locked_until timestamptz;
