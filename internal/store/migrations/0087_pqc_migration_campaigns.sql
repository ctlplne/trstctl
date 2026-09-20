-- SPDX-License-Identifier: BUSL-1.1

-- Core PQC migration campaigns turn tenant CBOM observations into an owned,
-- deadline-bound program. These tables are read-model projections only; immutable
-- pqc.migration_campaign.* events remain the source of truth (AN-2).
CREATE TABLE pqc_migration_campaigns (
    tenant_id UUID NOT NULL,
    id UUID NOT NULL,
    name TEXT NOT NULL,
    owner_ref TEXT NOT NULL,
    deadline TIMESTAMPTZ NOT NULL,
    wave TEXT NOT NULL,
    readiness_criteria TEXT[] NOT NULL DEFAULT '{}',
    readiness_status TEXT NOT NULL DEFAULT 'pending',
    readiness_evidence_refs TEXT[] NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'open',
    finding_count INTEGER NOT NULL DEFAULT 0,
    pending_count INTEGER NOT NULL DEFAULT 0,
    remediated_count INTEGER NOT NULL DEFAULT 0,
    excepted_count INTEGER NOT NULL DEFAULT 0,
    closure_jws TEXT NOT NULL DEFAULT '',
    closure_jwks JSONB,
    closed_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    closed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT pqc_migration_campaigns_name_chk CHECK (length(btrim(name)) > 0),
    CONSTRAINT pqc_migration_campaigns_owner_chk CHECK (length(btrim(owner_ref)) > 0),
    CONSTRAINT pqc_migration_campaigns_wave_chk CHECK (length(btrim(wave)) > 0),
    CONSTRAINT pqc_migration_campaigns_readiness_chk
        CHECK (readiness_status IN ('pending', 'passed', 'blocked')),
    CONSTRAINT pqc_migration_campaigns_status_chk CHECK (status IN ('open', 'closed')),
    CONSTRAINT pqc_migration_campaigns_counts_chk CHECK (
        finding_count >= 0 AND pending_count >= 0 AND remediated_count >= 0 AND excepted_count >= 0
        AND finding_count = pending_count + remediated_count + excepted_count
    )
);

CREATE TABLE pqc_migration_campaign_findings (
    tenant_id UUID NOT NULL,
    campaign_id UUID NOT NULL,
    finding_id UUID NOT NULL,
    finding_digest TEXT NOT NULL,
    kind TEXT NOT NULL,
    location TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT '',
    key_bits INTEGER NOT NULL DEFAULT 0,
    protocol TEXT NOT NULL DEFAULT '',
    cipher TEXT NOT NULL DEFAULT '',
    disposition TEXT NOT NULL DEFAULT 'pending',
    remediation_method TEXT NOT NULL DEFAULT '',
    disposition_reason TEXT NOT NULL DEFAULT '',
    evidence_refs TEXT[] NOT NULL DEFAULT '{}',
    evidence_digests TEXT[] NOT NULL DEFAULT '{}',
    dispositioned_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, campaign_id, finding_id),
    FOREIGN KEY (tenant_id, campaign_id)
        REFERENCES pqc_migration_campaigns (tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT pqc_migration_campaign_findings_digest_chk
        CHECK (finding_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT pqc_migration_campaign_findings_disposition_chk
        CHECK (disposition IN ('pending', 'remediated', 'excepted'))
);

CREATE INDEX pqc_migration_campaigns_tenant_id_idx
    ON pqc_migration_campaigns (tenant_id, id);
CREATE INDEX pqc_migration_campaign_findings_tenant_id_idx
    ON pqc_migration_campaign_findings (tenant_id, campaign_id, finding_id);

ALTER TABLE pqc_migration_campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE pqc_migration_campaigns FORCE ROW LEVEL SECURITY;
ALTER TABLE pqc_migration_campaign_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE pqc_migration_campaign_findings FORCE ROW LEVEL SECURITY;

CREATE POLICY pqc_migration_campaigns_isolation ON pqc_migration_campaigns
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
CREATE POLICY pqc_migration_campaign_findings_isolation ON pqc_migration_campaign_findings
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON pqc_migration_campaigns TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pqc_migration_campaign_findings TO trstctl_app;
