-- A14/A15: a static-provider schedule whose provider no longer (or never) allows
-- static rotation ends its due edge unsupported without a provider phase. The
-- closed last_error vocabulary gains that exact diagnostic class; the older
-- "until a durable worker owns …" text stays accepted for rows that recorded it.
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
        'scheduled static-provider rotation is unavailable: the provider does not allow static rotation',
        'scheduled rotation failed',
        'scheduled rotation rollback failed',
        'scheduled rotation is unavailable'
    ));
