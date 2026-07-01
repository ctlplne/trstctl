-- 0067_secret_rotation_schedules.sql -- CAP-SECR-06 scheduled dual-phase secret rotation.
--
-- secret_rotation_schedules is a tenant-scoped read model projected from
-- secret.rotation_schedule.* events. It stores only rotation metadata and stable
-- backend credential references; generated credential material stays inside the
-- configured rotator/provider and is never persisted here.

CREATE TABLE IF NOT EXISTS secret_rotation_schedules (
    id               uuid        NOT NULL,
    tenant_id        uuid        NOT NULL,
    name             text        NOT NULL,
    provider         text        NOT NULL,
    secret_key       text        NOT NULL,
    old_ref          text        NOT NULL,
    interval_seconds integer     NOT NULL,
    enabled          boolean     NOT NULL DEFAULT true,
    next_run_at      timestamptz NOT NULL,
    last_run_id      uuid,
    last_run_at      timestamptz,
    last_run_status  text        NOT NULL DEFAULT '',
    last_new_ref     text        NOT NULL DEFAULT '',
    last_error       text        NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL,
    updated_at       timestamptz NOT NULL,
    CONSTRAINT secret_rotation_schedules_required_chk
        CHECK (name <> '' AND provider <> '' AND secret_key <> '' AND old_ref <> ''),
    CONSTRAINT secret_rotation_schedules_interval_chk
        CHECK (interval_seconds > 0),
    PRIMARY KEY (tenant_id, id)
);

ALTER TABLE secret_rotation_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_rotation_schedules FORCE ROW LEVEL SECURITY;

CREATE POLICY secret_rotation_schedules_isolation ON secret_rotation_schedules
    USING (tenant_id::text = current_setting('trstctl.tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('trstctl.tenant_id', true));

CREATE UNIQUE INDEX IF NOT EXISTS secret_rotation_schedules_tenant_name_idx
    ON secret_rotation_schedules (tenant_id, name);

CREATE INDEX IF NOT EXISTS secret_rotation_schedules_tenant_due_idx
    ON secret_rotation_schedules (tenant_id, enabled, next_run_at, id);

GRANT SELECT, INSERT, UPDATE, DELETE ON secret_rotation_schedules TO trstctl_app;
