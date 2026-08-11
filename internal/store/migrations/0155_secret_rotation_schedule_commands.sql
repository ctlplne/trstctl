-- 0155_secret_rotation_schedule_commands.sql -- durable scheduled-rotation due-edge authority.
--
-- A schedule row says when work is due; it is not itself a claim on that exact
-- due edge. This independent PostgreSQL receiver binds one immutable command to
-- (tenant, schedule, due_at) before any connector mutation event/outbox is
-- committed. Lease columns coordinate live runners, while the command identity
-- and terminal receipt survive process crashes and event read-model rebuilds.

-- The scheduler must be able to distinguish the exact configuration it froze
-- from a later upsert. Existing projected rows predate this evidence and start at
-- sequence zero; the next event-derived upsert installs its real stream sequence.
ALTER TABLE secret_rotation_schedules
    ADD COLUMN IF NOT EXISTS config_event_sequence bigint NOT NULL DEFAULT 0;

ALTER TABLE secret_rotation_schedules
    DROP CONSTRAINT IF EXISTS secret_rotation_schedules_config_event_sequence_chk;
ALTER TABLE secret_rotation_schedules
    ADD CONSTRAINT secret_rotation_schedules_config_event_sequence_chk
        CHECK (config_event_sequence >= 0);

CREATE TABLE IF NOT EXISTS secret_rotation_schedule_commands (
    tenant_id        uuid        NOT NULL,
    schedule_id      uuid        NOT NULL,
    run_id           uuid        NOT NULL,
    due_at           timestamptz NOT NULL,
    provider         text        NOT NULL,
    secret_key       text        NOT NULL,
    old_ref          text        NOT NULL,
    interval_seconds integer     NOT NULL,
    config_event_sequence bigint NOT NULL,
    tick_idempotency_key text    NOT NULL,
    tick_ordinal       integer     NOT NULL,
    command_key      text        NOT NULL,
    request_binding  text        NOT NULL,
    terminal_event_id text       NOT NULL,
    prepared_status  text        NOT NULL DEFAULT '',
    prepared_new_ref text        NOT NULL DEFAULT '',
    prepared_error   text        NOT NULL DEFAULT '',
    prepared_event_digest text   NOT NULL DEFAULT '',
    prepared_at      timestamptz,
    terminal_event_type text     NOT NULL DEFAULT '',
    terminal_event_sequence bigint,
    terminal_event_digest text   NOT NULL DEFAULT '',
    terminal_event_from_event boolean,
    privacy_rewrite_version integer NOT NULL DEFAULT 0,
    privacy_subject_ref text     NOT NULL DEFAULT '',
    privacy_operation_id text    NOT NULL DEFAULT '',
    privacy_event_id text        NOT NULL DEFAULT '',
    status           text        NOT NULL DEFAULT 'claimed',
    new_ref          text        NOT NULL DEFAULT '',
    error            text        NOT NULL DEFAULT '',
    lease_token      text        NOT NULL DEFAULT '',
    lease_until      timestamptz,
    created_at       timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL,
    terminal_at      timestamptz,
    CONSTRAINT secret_rotation_schedule_commands_pk
        PRIMARY KEY (tenant_id, run_id),
    CONSTRAINT secret_rotation_schedule_commands_due_uq
        UNIQUE (tenant_id, schedule_id, due_at),
    CONSTRAINT secret_rotation_schedule_commands_identity_chk
        CHECK (provider <> '' AND secret_key <> '' AND old_ref <> '' AND
               interval_seconds > 0 AND config_event_sequence > 0 AND
               tick_idempotency_key <> '' AND tick_ordinal > 0 AND tick_ordinal <= 500 AND
               command_key <> '' AND request_binding <> '' AND terminal_event_id <> ''),
    CONSTRAINT secret_rotation_schedule_commands_status_chk
        CHECK (status IN (
            'claimed', 'completed', 'queued', 'failed', 'rolled_back',
            'rollback_failed', 'retire_pending', 'delivery_failed', 'unsupported',
            'privacy_erased'
        )),
    CONSTRAINT secret_rotation_schedule_commands_prepared_chk
        CHECK (
            (prepared_status = '' AND prepared_new_ref = '' AND
             prepared_error = '' AND prepared_event_digest = '' AND
             prepared_at IS NULL)
            OR
            (prepared_status IN (
                'completed', 'queued', 'failed', 'rolled_back',
                'rollback_failed', 'retire_pending', 'delivery_failed', 'unsupported'
             ) AND prepared_event_digest ~ '^[0-9a-f]{64}$' AND
             prepared_at IS NOT NULL)
            OR
            (status = 'privacy_erased' AND prepared_status = '' AND
             prepared_event_digest = '' AND prepared_at IS NULL)
        ),
    CONSTRAINT secret_rotation_schedule_commands_lease_chk
        CHECK ((lease_token = '') = (lease_until IS NULL)),
    CONSTRAINT secret_rotation_schedule_commands_privacy_chk
        CHECK (
            (privacy_rewrite_version = 0 AND privacy_subject_ref = '' AND
             privacy_operation_id = '' AND privacy_event_id = '' AND
             status <> 'privacy_erased')
            OR
            (privacy_rewrite_version = 1 AND
             privacy_subject_ref ~ '^[0-9a-f]{64}$' AND
             privacy_operation_id ~ '^sha256:[0-9a-f]{64}$' AND
             privacy_event_id ~ '^sha256:[0-9a-f]{64}$' AND
             status = 'privacy_erased')
        ),
    CONSTRAINT secret_rotation_schedule_commands_terminal_chk
        CHECK (
            (status = 'claimed'
                AND terminal_at IS NULL
                AND terminal_event_type = ''
                AND terminal_event_sequence IS NULL
                AND terminal_event_digest = ''
                AND terminal_event_from_event IS NULL)
            OR
            (status IN (
                    'completed', 'queued', 'failed', 'rolled_back',
                    'rollback_failed', 'retire_pending', 'delivery_failed', 'unsupported'
                )
                AND terminal_at IS NOT NULL
                AND lease_token = ''
                AND lease_until IS NULL
                AND terminal_event_type = 'secret.rotation_schedule.ran'
                AND terminal_event_sequence IS NOT NULL
                AND terminal_event_sequence > 0
                AND terminal_event_digest ~ '^[0-9a-f]{64}$'
                AND terminal_event_from_event IS TRUE
                AND prepared_status = status
                AND prepared_new_ref = new_ref
                AND prepared_error = error
                AND prepared_event_digest = terminal_event_digest
                AND prepared_at = terminal_at)
            OR
            (status = 'privacy_erased'
                AND terminal_at IS NOT NULL
                AND lease_token = '' AND lease_until IS NULL
                AND prepared_status = '' AND prepared_event_digest = ''
                AND prepared_at IS NULL
                AND terminal_event_type = ''
                AND terminal_event_sequence IS NULL
                AND terminal_event_digest = ''
                AND terminal_event_from_event IS NULL)
        )
);

ALTER TABLE secret_rotation_schedule_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_rotation_schedule_commands FORCE ROW LEVEL SECURITY;

CREATE POLICY secret_rotation_schedule_commands_isolation
    ON secret_rotation_schedule_commands
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));

CREATE INDEX IF NOT EXISTS secret_rotation_schedule_commands_claim_idx
    ON secret_rotation_schedule_commands (tenant_id, status, lease_until, due_at, schedule_id);

-- One operational cursor per tenant makes bounded due scans fair across ticks.
-- UUID order is stable even when next_run_at changes. The cursor has no foreign
-- key because a referenced schedule may be deleted or rebuilt; the next scan
-- simply continues after that UUID and wraps once at the end of the ring.
CREATE TABLE IF NOT EXISTS secret_rotation_schedule_scan_cursors (
    tenant_id          uuid        NOT NULL,
    after_schedule_id  uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    active_tick_key    text        NOT NULL DEFAULT '',
    active_tick_binding text       NOT NULL DEFAULT '',
    lease_token        text        NOT NULL DEFAULT '',
    lease_until        timestamptz,
    lease_generation   bigint      NOT NULL DEFAULT 0,
    generation         bigint      NOT NULL DEFAULT 0,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT secret_rotation_schedule_scan_cursors_pk PRIMARY KEY (tenant_id),
    CONSTRAINT secret_rotation_schedule_scan_cursors_lease_chk
        CHECK ((lease_token = '') = (lease_until IS NULL) AND
               (lease_token = '') = (active_tick_key = '') AND
               (lease_token = '') = (active_tick_binding = '')),
    CONSTRAINT secret_rotation_schedule_scan_cursors_lease_generation_chk
        CHECK (lease_generation >= 0),
    CONSTRAINT secret_rotation_schedule_scan_cursors_generation_chk
        CHECK (generation >= 0)
);

ALTER TABLE secret_rotation_schedule_scan_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_rotation_schedule_scan_cursors FORCE ROW LEVEL SECURITY;

CREATE POLICY secret_rotation_schedule_scan_cursors_isolation
    ON secret_rotation_schedule_scan_cursors
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));

-- A scheduler HTTP key is itself a durable aggregate command. This receiver
-- freezes the PostgreSQL-owned cutoff and start cursor, then retains the exact
-- ordered partial receipt and logical budgets across process crashes. It is
-- independent of the event-derived schedule projection and has no FK to it.
CREATE TABLE IF NOT EXISTS secret_rotation_schedule_ticks (
    tenant_id             uuid        NOT NULL,
    idempotency_key       text        NOT NULL,
    request_binding       text        NOT NULL,
    due_through           timestamptz NOT NULL,
    start_schedule_id     uuid        NOT NULL,
    after_schedule_id     uuid        NOT NULL,
    wrapped               boolean     NOT NULL DEFAULT false,
    phase                 text        NOT NULL DEFAULT 'ready',
    current_schedule_id   uuid,
    current_due_at        timestamptz,
    current_provider      text,
    current_secret_key    text,
    current_old_ref       text,
    current_interval_seconds integer,
    current_config_event_sequence bigint,
    current_command_lease_token text,
    ran                   integer     NOT NULL DEFAULT 0,
    scanned               integer     NOT NULL DEFAULT 0,
    snapshot_count        integer     NOT NULL,
    receipt               jsonb       NOT NULL,
    owner_token           text        NOT NULL,
    owner_generation      bigint      NOT NULL,
    terminal_http_status  integer,
    terminal_body         bytea,
    privacy_rewrite_version integer NOT NULL DEFAULT 0,
    privacy_subject_ref   text        NOT NULL DEFAULT '',
    privacy_operation_id  text        NOT NULL DEFAULT '',
    privacy_event_id      text        NOT NULL DEFAULT '',
    created_at            timestamptz NOT NULL,
    updated_at            timestamptz NOT NULL,
    completed_at          timestamptz,
    CONSTRAINT secret_rotation_schedule_ticks_pk
        PRIMARY KEY (tenant_id, idempotency_key),
    CONSTRAINT secret_rotation_schedule_ticks_idempotency_fk
        FOREIGN KEY (tenant_id, idempotency_key)
        REFERENCES idempotency_keys (tenant_id, key)
        ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT secret_rotation_schedule_ticks_identity_chk
        CHECK (idempotency_key <> '' AND request_binding <> ''),
    CONSTRAINT secret_rotation_schedule_ticks_phase_chk
        CHECK (phase IN ('ready', 'row_started', 'terminal', 'privacy_erased')),
    CONSTRAINT secret_rotation_schedule_ticks_budget_chk
        CHECK (ran >= 0 AND ran <= 50 AND scanned >= 0 AND scanned <= 500 AND
               ran <= scanned AND snapshot_count >= 0 AND snapshot_count <= 500 AND
               scanned <= snapshot_count),
    CONSTRAINT secret_rotation_schedule_ticks_owner_chk
        CHECK (owner_generation > 0 AND
               ((phase IN ('terminal', 'privacy_erased') AND owner_token = '') OR
                (phase NOT IN ('terminal', 'privacy_erased') AND owner_token <> ''))),
    CONSTRAINT secret_rotation_schedule_ticks_privacy_chk
        CHECK (
            (privacy_rewrite_version = 0 AND privacy_subject_ref = '' AND
             privacy_operation_id = '' AND privacy_event_id = '' AND
             phase <> 'privacy_erased')
            OR
            (privacy_rewrite_version = 1 AND
             privacy_subject_ref ~ '^[0-9a-f]{64}$' AND
             privacy_operation_id ~ '^sha256:[0-9a-f]{64}$' AND
             privacy_event_id ~ '^sha256:[0-9a-f]{64}$' AND
             phase = 'privacy_erased')
        ),
    CONSTRAINT secret_rotation_schedule_ticks_current_chk
        CHECK (
            (phase = 'row_started' AND
             current_schedule_id IS NOT NULL AND current_due_at IS NOT NULL AND
             current_provider IS NOT NULL AND current_secret_key IS NOT NULL AND
             current_old_ref IS NOT NULL AND current_interval_seconds IS NOT NULL AND
             current_config_event_sequence IS NOT NULL AND current_config_event_sequence >= 0 AND
             current_command_lease_token IS NOT NULL AND current_command_lease_token <> '')
            OR
            (phase <> 'row_started' AND
             current_schedule_id IS NULL AND current_due_at IS NULL AND
             current_provider IS NULL AND current_secret_key IS NULL AND
             current_old_ref IS NULL AND current_interval_seconds IS NULL AND
             current_config_event_sequence IS NULL AND
             current_command_lease_token IS NULL)
        ),
    CONSTRAINT secret_rotation_schedule_ticks_terminal_chk
        CHECK (
            (phase = 'terminal' AND terminal_http_status IN (200, 503) AND
             terminal_body IS NOT NULL AND completed_at IS NOT NULL)
            OR
            (phase = 'privacy_erased' AND completed_at IS NOT NULL AND
             (terminal_http_status IS NULL) = (terminal_body IS NULL) AND
             (terminal_http_status IS NULL OR terminal_http_status IN (200, 503)))
            OR
            (phase NOT IN ('terminal', 'privacy_erased') AND terminal_http_status IS NULL AND
             terminal_body IS NULL AND completed_at IS NULL)
        )
);

ALTER TABLE secret_rotation_schedule_ticks ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_rotation_schedule_ticks FORCE ROW LEVEL SECURITY;

CREATE POLICY secret_rotation_schedule_ticks_isolation
    ON secret_rotation_schedule_ticks
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));

CREATE INDEX IF NOT EXISTS secret_rotation_schedule_ticks_completed_idx
    ON secret_rotation_schedule_ticks (tenant_id, completed_at, idempotency_key)
    WHERE completed_at IS NOT NULL;

-- These rows are the immutable work membership and exact non-secret schedule
-- tuples frozen in the same transaction as the outer Idempotency-Key. Ordinal is
-- the only traversal cursor: retries never query the mutable schedule projection
-- to rediscover membership or configuration.
CREATE TABLE IF NOT EXISTS secret_rotation_schedule_tick_rows (
    tenant_id             uuid        NOT NULL,
    idempotency_key       text        NOT NULL,
    ordinal               integer     NOT NULL,
    schedule_id           uuid        NOT NULL,
    due_at                timestamptz NOT NULL,
    provider              text        NOT NULL,
    secret_key            text        NOT NULL,
    old_ref               text        NOT NULL,
    interval_seconds      integer     NOT NULL,
    config_event_sequence bigint      NOT NULL,
    CONSTRAINT secret_rotation_schedule_tick_rows_pk
        PRIMARY KEY (tenant_id, idempotency_key, ordinal),
    CONSTRAINT secret_rotation_schedule_tick_rows_schedule_uq
        UNIQUE (tenant_id, idempotency_key, schedule_id),
    CONSTRAINT secret_rotation_schedule_tick_rows_tick_fk
        FOREIGN KEY (tenant_id, idempotency_key)
        REFERENCES secret_rotation_schedule_ticks (tenant_id, idempotency_key)
        ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT secret_rotation_schedule_tick_rows_shape_chk
        CHECK (ordinal > 0 AND ordinal <= 500 AND provider <> '' AND
               secret_key <> '' AND old_ref <> '' AND interval_seconds > 0 AND
               config_event_sequence >= 0)
);

ALTER TABLE secret_rotation_schedule_tick_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_rotation_schedule_tick_rows FORCE ROW LEVEL SECURITY;

CREATE POLICY secret_rotation_schedule_tick_rows_isolation
    ON secret_rotation_schedule_tick_rows
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));

-- The application role may create only the immutable claimed tuple (status and
-- terminal receipt columns are omitted and therefore take their safe defaults),
-- then mutate only its operational lease. The owner-role event projector is the
-- sole terminal writer; direct SQL cannot manufacture completion evidence.
REVOKE ALL ON secret_rotation_schedule_commands FROM trstctl_app;
GRANT SELECT ON secret_rotation_schedule_commands TO trstctl_app;
GRANT INSERT (
    tenant_id, schedule_id, run_id, due_at, provider, secret_key, old_ref,
    interval_seconds, config_event_sequence, tick_idempotency_key, tick_ordinal,
    command_key, request_binding, terminal_event_id,
    lease_token, lease_until, created_at, updated_at
) ON secret_rotation_schedule_commands TO trstctl_app;
GRANT UPDATE (lease_token, lease_until, updated_at)
    ON secret_rotation_schedule_commands TO trstctl_app;

REVOKE ALL ON secret_rotation_schedule_scan_cursors FROM trstctl_app;
GRANT SELECT ON secret_rotation_schedule_scan_cursors TO trstctl_app;

-- Tick progress, receipts, cursor movement, and terminal bytes are written only
-- by narrow owner-role store methods that CAS the live token+generation while
-- locking cursor -> tick -> optional child command. The application role may
-- inspect its RLS-visible authority but cannot forge progress or completion.
REVOKE ALL ON secret_rotation_schedule_ticks FROM trstctl_app;
GRANT SELECT ON secret_rotation_schedule_ticks TO trstctl_app;

REVOKE ALL ON secret_rotation_schedule_tick_rows FROM trstctl_app;
GRANT SELECT ON secret_rotation_schedule_tick_rows TO trstctl_app;

-- Deliberately no foreign key points at secret_rotation_schedules. Schedules are
-- a rebuildable event projection; PostgreSQL command receivers are independent
-- recovery authority and must survive TRUNCATE ... CASCADE during a full replay.
-- Tenant offboarding and the verified terminal-command sweeper use narrow
-- owner-role store methods because trstctl_app has no DELETE privilege here.
-- Scan cursors are likewise independent operational authority. They are
-- bounded to one row per tenant, so no runtime GC is needed; tenant offboarding
-- deletes them under the owner role and PostgreSQL backup/restore preserves them.
