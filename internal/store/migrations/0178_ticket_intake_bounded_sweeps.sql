-- SPDX-License-Identifier: BUSL-1.1

-- AUD-47: ServiceNow and Jira share one tenant-scoped scheduled intake model.
-- A sweep is a named chain of signed, bounded relay pages. last_run_at remains
-- the last COMPLETE sweep, never the time a job was merely queued.
ALTER TABLE ticket_intake_schedules
    ADD COLUMN jira_project text NOT NULL DEFAULT '',
    ADD COLUMN current_sweep_id uuid,
    ADD COLUMN sweep_started_at timestamptz,
    ADD COLUMN last_attempt_at timestamptz,
    ADD COLUMN cursor text NOT NULL DEFAULT '',
    ADD COLUMN read_count integer NOT NULL DEFAULT 0,
    ADD COLUMN expected_count integer,
    ADD COLUMN pages_completed integer NOT NULL DEFAULT 0,
    ADD COLUMN coverage_complete boolean NOT NULL DEFAULT false,
    ADD COLUMN eligible_count integer NOT NULL DEFAULT 0,
    ADD COLUMN skipped_count integer NOT NULL DEFAULT 0;

ALTER TABLE ticket_intake_schedules
    DROP CONSTRAINT ticket_intake_system_known,
    DROP CONSTRAINT ticket_intake_table_known,
    ADD CONSTRAINT ticket_intake_system_known CHECK (system IN ('servicenow', 'jira')),
    ADD CONSTRAINT ticket_intake_provider_shape CHECK (
        (system = 'servicenow'
         AND sn_table IN ('incident', 'sc_req_item', 'sc_request', 'change_request')
         AND jira_project = '')
        OR
        (system = 'jira'
         AND sn_table = ''
         AND jira_project ~ '^[A-Z][A-Z0-9_]{0,63}$')
    ),
    ADD CONSTRAINT ticket_intake_progress_nonnegative CHECK (
        read_count >= 0 AND pages_completed >= 0 AND eligible_count >= 0
        AND skipped_count >= 0
        AND (expected_count IS NULL OR expected_count >= read_count)
    ),
    ADD CONSTRAINT ticket_intake_progress_identity CHECK (
        (current_sweep_id IS NULL AND sweep_started_at IS NULL AND cursor = ''
         AND read_count = 0 AND expected_count IS NULL AND pages_completed = 0
         AND NOT coverage_complete AND eligible_count = 0 AND skipped_count = 0)
        OR (current_sweep_id IS NOT NULL AND sweep_started_at IS NOT NULL)
    );

COMMENT ON COLUMN ticket_intake_schedules.cursor IS
    'Exact next-page authority: last ServiceNow sys_id or opaque Jira nextPageToken for current_sweep_id.';
COMMENT ON COLUMN ticket_intake_schedules.coverage_complete IS
    'True only after the relay reports the provider terminal page; dispatch is never success.';

-- Pre-AUD-47 rows cannot be bound to a provider sweep/cursor. Retire only
-- those pending/claimed legacy commands. The enabled schedule dispatches a
-- fresh named sweep on the next leader pass.
UPDATE outbox
   SET status = 'failed',
       last_error = 'retired during bounded ticket-intake migration; the schedule will restart as a named provider sweep',
       worker_id = NULL,
       lease_until = NULL,
       claimed_by_agent_id = NULL,
       claim_expires_at = NULL
 WHERE destination = 'ticket.sync'
   AND status IN ('pending', 'processing')
   AND convert_from(payload, 'UTF8')::jsonb ->> 'sweep_id' IS NULL;
