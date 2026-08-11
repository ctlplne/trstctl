-- 0161_secret_rotation_schedule_error_vocabulary.sql -- close historical scheduler diagnostics.
--
-- Version-1 scheduled rotation events and their read-model rows predate the
-- closed error vocabulary. A provider could therefore leave arbitrary text in
-- last_error. Collapse existing rows to stable product-owned classes and make
-- the database reject any future projection that tries to restore raw text.

UPDATE secret_rotation_schedules
   SET last_error = CASE
       WHEN last_error = '' THEN ''
       WHEN last_error IN (
           'connector delivery failed',
           'application-secret approval is no longer usable',
           'no such secret',
           'resource not found',
           'approval requester cannot approve their own request',
           'approval request expired',
           'approval request superseded',
           'approval authority already consumed',
           'approval target version or state drifted',
           'approval request has not reached quorum',
           'connector rotation target is required',
           'secret sync target is not configured',
           'connector rotation old_ref must be version:<n>',
           'connector rotation old_ref does not name the current version',
           'dynamic-lease rotation is unavailable until its issue, delivery, and predecessor retirement phases share one durable worker command',
           'scheduled static-provider rotation is unavailable until a durable worker owns stage, cutover, verification, rollback, and retirement',
           'scheduled rotation failed',
           'scheduled rotation rollback failed',
           'scheduled rotation is unavailable'
       ) THEN last_error
       WHEN last_run_status IN ('completed', 'queued') THEN ''
       WHEN last_run_status = 'delivery_failed' THEN 'connector delivery failed'
       WHEN last_run_status = 'rollback_failed' THEN 'scheduled rotation rollback failed'
       WHEN last_run_status = 'unsupported' THEN 'scheduled rotation is unavailable'
       ELSE 'scheduled rotation failed'
   END;

ALTER TABLE secret_rotation_schedules
    DROP CONSTRAINT IF EXISTS secret_rotation_schedules_last_error_closed_chk;
ALTER TABLE secret_rotation_schedules
    ADD CONSTRAINT secret_rotation_schedules_last_error_closed_chk
    CHECK (last_error IN (
        '',
        'connector delivery failed',
        'application-secret approval is no longer usable',
        'no such secret',
        'resource not found',
        'approval requester cannot approve their own request',
        'approval request expired',
        'approval request superseded',
        'approval authority already consumed',
        'approval target version or state drifted',
        'approval request has not reached quorum',
        'connector rotation target is required',
        'secret sync target is not configured',
        'connector rotation old_ref must be version:<n>',
        'connector rotation old_ref does not name the current version',
        'dynamic-lease rotation is unavailable until its issue, delivery, and predecessor retirement phases share one durable worker command',
        'scheduled static-provider rotation is unavailable until a durable worker owns stage, cutover, verification, rollback, and retirement',
        'scheduled rotation failed',
        'scheduled rotation rollback failed',
        'scheduled rotation is unavailable'
    ));

COMMENT ON COLUMN secret_rotation_schedules.last_error IS
    'Closed scheduler-owned diagnostic class; never provider or storage error text.';
