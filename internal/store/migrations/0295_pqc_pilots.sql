-- SPDX-License-Identifier: BUSL-1.1

-- PQC pilot waves (A28/A29, epic M1/H2): a pilot rolls a post-quantum leaf's
-- handshake proof out in ordered waves — a small canary first — and halts the
-- instant a wave's evidence says to. These tables are read-model projections
-- only; immutable pqc.pilot.* events remain the source of truth (AN-2).
CREATE TABLE pqc_pilots (
    tenant_id UUID NOT NULL,
    id UUID NOT NULL,
    name TEXT NOT NULL,
    authority_id TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'running',
    wave_count INTEGER NOT NULL,
    current_wave INTEGER NOT NULL DEFAULT 0,
    halted_at_wave TEXT NOT NULL DEFAULT '',
    verdict_summary TEXT NOT NULL DEFAULT '',
    signed_report TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT pqc_pilots_name_chk CHECK (length(btrim(name)) > 0),
    CONSTRAINT pqc_pilots_status_chk CHECK (status IN ('running', 'halted', 'completed')),
    CONSTRAINT pqc_pilots_waves_chk CHECK (wave_count > 0 AND current_wave >= 0 AND current_wave <= wave_count)
);

CREATE TABLE pqc_pilot_waves (
    tenant_id UUID NOT NULL,
    pilot_id UUID NOT NULL,
    wave_index INTEGER NOT NULL,
    name TEXT NOT NULL,
    targets JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    outbox_id BIGINT,
    idempotency_key TEXT NOT NULL DEFAULT '',
    results JSONB,
    verdict JSONB,
    dispatched_at TIMESTAMPTZ,
    assessed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, pilot_id, wave_index),
    FOREIGN KEY (tenant_id, pilot_id) REFERENCES pqc_pilots (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT pqc_pilot_waves_index_chk CHECK (wave_index > 0),
    CONSTRAINT pqc_pilot_waves_name_chk CHECK (length(btrim(name)) > 0),
    CONSTRAINT pqc_pilot_waves_status_chk CHECK (status IN ('pending', 'probing', 'assessed', 'skipped'))
);

ALTER TABLE pqc_pilots ENABLE ROW LEVEL SECURITY;
ALTER TABLE pqc_pilots FORCE ROW LEVEL SECURITY;
CREATE POLICY pqc_pilots_tenant_isolation ON pqc_pilots
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
ALTER TABLE pqc_pilot_waves ENABLE ROW LEVEL SECURITY;
ALTER TABLE pqc_pilot_waves FORCE ROW LEVEL SECURITY;
CREATE POLICY pqc_pilot_waves_tenant_isolation ON pqc_pilot_waves
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON pqc_pilots TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pqc_pilot_waves TO trstctl_app;
