-- SPDX-License-Identifier: BUSL-1.1

-- Tenant-authored workload-identity sources for outbound secret sync. Rows hold
-- policy and reference metadata only. Workload proof bytes and short-lived cloud
-- credentials are resolved/minted only inside the bounded outbox worker and are
-- never written here (AN-6/AN-8).
CREATE TABLE secret_sync_workload_identity_sources (
    tenant_id UUID NOT NULL,
    id UUID NOT NULL,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    role_arn TEXT NOT NULL,
    audience TEXT NOT NULL,
    subject TEXT NOT NULL,
    target_id TEXT NOT NULL,
    allowed_remote_key_prefixes TEXT[] NOT NULL DEFAULT '{}',
    workload_proof_ref TEXT NOT NULL,
    trust_source_id UUID NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    status TEXT NOT NULL DEFAULT 'ready',
    status_reason TEXT NOT NULL DEFAULT '',
    last_exchange_at TIMESTAMPTZ,
    token_expires_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, provider, target_id),
    FOREIGN KEY (tenant_id, trust_source_id)
        REFERENCES workload_attester_trust_sources (tenant_id, id)
        ON DELETE RESTRICT,
    CONSTRAINT secret_sync_workload_identity_provider_chk
        CHECK (provider IN ('aws')),
    CONSTRAINT secret_sync_workload_identity_name_chk
        CHECK (length(btrim(name)) > 0),
    CONSTRAINT secret_sync_workload_identity_role_chk
        CHECK (length(btrim(role_arn)) > 0),
    CONSTRAINT secret_sync_workload_identity_audience_chk
        CHECK (length(btrim(audience)) > 0),
    CONSTRAINT secret_sync_workload_identity_subject_chk
        CHECK (length(btrim(subject)) > 0),
    CONSTRAINT secret_sync_workload_identity_target_chk
        CHECK (length(btrim(target_id)) > 0),
    CONSTRAINT secret_sync_workload_identity_proof_ref_chk
        CHECK (workload_proof_ref LIKE 'file:%' OR workload_proof_ref LIKE 'secret://%'),
    CONSTRAINT secret_sync_workload_identity_status_chk
        CHECK (status IN ('ready', 'active', 'disabled', 'offline_disabled', 'exchange_failed'))
);

CREATE INDEX secret_sync_workload_identity_sources_tenant_status_idx
    ON secret_sync_workload_identity_sources (tenant_id, provider, enabled, status, id);

ALTER TABLE secret_sync_workload_identity_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE secret_sync_workload_identity_sources FORCE ROW LEVEL SECURITY;

CREATE POLICY secret_sync_workload_identity_sources_isolation
    ON secret_sync_workload_identity_sources
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON secret_sync_workload_identity_sources TO trstctl_app;
