-- SPDX-License-Identifier: BUSL-1.1

-- AUD-46: one CMDB sweep is a chain of bounded, sys_id-keyset pages. These
-- columns are the tenant-local checkpoint operators read and the scheduler
-- resumes. last_run_at remains NULL until the first short/empty terminal page;
-- dispatch and a full page are progress, not success.
ALTER TABLE cmdb_reconcile_schedules
    ADD COLUMN current_sweep_id uuid,
    ADD COLUMN sweep_started_at timestamptz,
    ADD COLUMN last_attempt_at timestamptz,
    ADD COLUMN after_sys_id text NOT NULL DEFAULT '',
    ADD COLUMN read_count integer NOT NULL DEFAULT 0,
    ADD COLUMN expected_count integer,
    ADD COLUMN pages_completed integer NOT NULL DEFAULT 0,
    ADD COLUMN coverage_complete boolean NOT NULL DEFAULT false,
    ADD COLUMN removed_count integer NOT NULL DEFAULT 0,
    ADD COLUMN changed_count integer NOT NULL DEFAULT 0;

ALTER TABLE cmdb_reconcile_schedules
    ADD CONSTRAINT cmdb_reconcile_progress_nonnegative CHECK (
        read_count >= 0 AND pages_completed >= 0 AND removed_count >= 0 AND changed_count >= 0
        AND (expected_count IS NULL OR expected_count >= 0)
    ),
    ADD CONSTRAINT cmdb_reconcile_progress_identity CHECK (
        (current_sweep_id IS NULL AND sweep_started_at IS NULL AND after_sys_id = ''
         AND read_count = 0 AND expected_count IS NULL AND pages_completed = 0
         AND NOT coverage_complete AND removed_count = 0 AND changed_count = 0)
        OR (current_sweep_id IS NOT NULL AND sweep_started_at IS NOT NULL)
    );

COMMENT ON COLUMN cmdb_reconcile_schedules.after_sys_id IS
    'Last strictly ordered cmdb_ci.sys_id committed for current_sweep_id; the next relay page reads sys_id greater than this value.';
COMMENT ON COLUMN cmdb_reconcile_schedules.coverage_complete IS
    'True only after a short or empty terminal page; dispatch and full pages never set this success bit.';

-- A pre-AUD-46 job has no sweep/cursor identity. Letting a new receiver ingest
-- it would either reject forever or apply owner changes that cannot advance the
-- new checkpoint. Retire only those legacy commands; their schedules have the
-- fresh NULL current_sweep_id above and will dispatch a named sweep on the next
-- leader tick.
UPDATE outbox
   SET status = 'failed',
       last_error = 'retired during bounded CMDB pagination migration; the schedule will restart as a named keyset sweep',
       worker_id = NULL,
       lease_until = NULL,
       claimed_by_agent_id = NULL,
       claim_expires_at = NULL
 WHERE destination = 'cmdb.sync'
   AND status IN ('pending', 'processing')
   AND convert_from(payload, 'UTF8')::jsonb ->> 'sweep_id' IS NULL;

-- One bounded inventory row per CMDB CI. This is not a copy of cmdb_ci: it
-- retains only the immutable source key, the matched trstctl owner id, and the
-- four ownership values needed to undo a source-only claim safely when the CI
-- disappears or moves owners. No CMDB token, arbitrary attributes, or owner
-- display name is stored here.
CREATE TABLE cmdb_ci_inventory (
    tenant_id              uuid NOT NULL,
    source_ref             text NOT NULL,
    owner_id               uuid,
    application_id         text NOT NULL DEFAULT '',
    service                text NOT NULL DEFAULT '',
    business_unit          text NOT NULL DEFAULT '',
    environment            text NOT NULL DEFAULT '',
    last_seen_sweep_id     uuid NOT NULL,
    last_seen_at           timestamptz NOT NULL,
    prior_owner_id         uuid,
    prior_present          boolean NOT NULL DEFAULT false,
    prior_application_id   text NOT NULL DEFAULT '',
    prior_service          text NOT NULL DEFAULT '',
    prior_business_unit    text NOT NULL DEFAULT '',
    prior_environment      text NOT NULL DEFAULT '',
    removed_at             timestamptz,
    PRIMARY KEY (tenant_id, source_ref),
    CHECK (source_ref ~ '^[A-Za-z0-9_.-]{1,128}$')
);

CREATE INDEX cmdb_ci_inventory_sweep_idx
    ON cmdb_ci_inventory (tenant_id, last_seen_sweep_id, source_ref);
CREATE INDEX cmdb_ci_inventory_owner_idx
    ON cmdb_ci_inventory (tenant_id, owner_id)
    WHERE owner_id IS NOT NULL AND removed_at IS NULL;

ALTER TABLE cmdb_ci_inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE cmdb_ci_inventory FORCE ROW LEVEL SECURITY;

CREATE POLICY cmdb_ci_inventory_tenant_isolation ON cmdb_ci_inventory
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON cmdb_ci_inventory TO trstctl_app;
