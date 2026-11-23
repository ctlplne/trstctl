-- SPDX-License-Identifier: BUSL-1.1
-- Installed before any ordinary migration or restore file mutation. The
-- matching migration supplies the tenant reservation and runtime read grant.
CREATE SCHEMA IF NOT EXISTS trstctl_recovery;

CREATE TABLE IF NOT EXISTS trstctl_recovery.restore_markers (
    tenant_id UUID PRIMARY KEY
        CHECK (tenant_id = '00000000-0000-0000-0000-000000000004'::uuid),
    operation_id UUID NOT NULL,
    artifact_sha256 CHAR(64) NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    event_cut BIGINT NOT NULL CHECK (event_cut >= 0),
    deployment_id TEXT NOT NULL CHECK (deployment_id <> ''),
    phase TEXT NOT NULL CHECK (phase IN ('prepared', 'artifacts_restored',
        'event_partial', 'postgres_imported', 'pair_verified', 'final_rebuild')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE trstctl_recovery.restore_markers
    ADD COLUMN IF NOT EXISTS event_history_sha256 CHAR(64)
    CHECK (event_history_sha256 ~ '^[0-9a-f]{64}$');
ALTER TABLE trstctl_recovery.restore_markers ENABLE ROW LEVEL SECURITY;
ALTER TABLE trstctl_recovery.restore_markers FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS restore_markers_control_isolation ON trstctl_recovery.restore_markers;
CREATE POLICY restore_markers_control_isolation
    ON trstctl_recovery.restore_markers
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid
        AND tenant_id = '00000000-0000-0000-0000-000000000004'::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid
        AND tenant_id = '00000000-0000-0000-0000-000000000004'::uuid);

CREATE TABLE IF NOT EXISTS trstctl_recovery.restore_activity_tokens (
    tenant_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    activity_kind TEXT NOT NULL CHECK (activity_kind IN
        ('request', 'build', 'worker', 'maintenance', 'backup', 'effect', 'ingress', 'projection')),
    lane TEXT NOT NULL CHECK (lane <> ''),
    phase TEXT NOT NULL DEFAULT 'started' CHECK (phase IN ('started', 'terminal')),
    event_id TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    terminal_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT restore_activity_terminal_chk CHECK
        ((phase = 'started' AND terminal_at IS NULL) OR
         (phase = 'terminal' AND terminal_at IS NOT NULL))
);
ALTER TABLE trstctl_recovery.restore_activity_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE trstctl_recovery.restore_activity_tokens FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS restore_activity_tenant_isolation ON trstctl_recovery.restore_activity_tokens;
CREATE POLICY restore_activity_tenant_isolation
    ON trstctl_recovery.restore_activity_tokens
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- The normal migration grants application-role read access after that role
-- exists; bootstrap needs only the owner-only target-local journal and RLS.
CREATE TABLE IF NOT EXISTS trstctl_recovery.event_ingress_journal (
    tenant_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    event_id TEXT NOT NULL CHECK (event_id <> ''),
    event_type TEXT NOT NULL CHECK (event_type <> ''),
    producer_tenant_scope TEXT NOT NULL CHECK (producer_tenant_scope <> ''),
    producer_key_id TEXT NOT NULL CHECK (producer_key_id <> ''),
    producer_mac BYTEA NOT NULL CHECK (octet_length(producer_mac) = 32),
    explicit_time BOOLEAN NOT NULL,
    attempted_wire_sha256 CHAR(64) CHECK (attempted_wire_sha256 ~ '^[0-9a-f]{64}$'),
    canonical_wire_sha256 CHAR(64) CHECK (canonical_wire_sha256 ~ '^[0-9a-f]{64}$'),
    canonical_sequence BIGINT CHECK (canonical_sequence > 0),
    phase TEXT NOT NULL DEFAULT 'started' CHECK (phase IN
        ('started', 'candidate_staged', 'published_verified', 'duplicate_verified', 'no_publication_verified')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, operation_id),
    CONSTRAINT event_ingress_journal_phase_chk CHECK (
        (phase = 'started' AND attempted_wire_sha256 IS NULL
            AND canonical_wire_sha256 IS NULL AND canonical_sequence IS NULL AND verified_at IS NULL) OR
        (phase = 'candidate_staged' AND attempted_wire_sha256 IS NOT NULL
            AND canonical_wire_sha256 IS NULL AND canonical_sequence IS NULL AND verified_at IS NULL) OR
        (phase = 'published_verified' AND attempted_wire_sha256 IS NOT NULL
            AND canonical_wire_sha256 IS NOT NULL AND canonical_sequence IS NOT NULL AND verified_at IS NOT NULL) OR
        (phase = 'duplicate_verified' AND canonical_wire_sha256 IS NOT NULL
            AND canonical_sequence IS NOT NULL AND verified_at IS NOT NULL) OR
        (phase = 'no_publication_verified' AND canonical_wire_sha256 IS NULL
            AND canonical_sequence IS NULL AND verified_at IS NOT NULL))
);
ALTER TABLE trstctl_recovery.event_ingress_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE trstctl_recovery.event_ingress_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS event_ingress_journal_tenant_isolation ON trstctl_recovery.event_ingress_journal;
CREATE POLICY event_ingress_journal_tenant_isolation
    ON trstctl_recovery.event_ingress_journal
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
