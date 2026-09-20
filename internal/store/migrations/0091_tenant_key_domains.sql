-- SPDX-License-Identifier: BUSL-1.1

-- tenant_key_domains is the tenant-scoped read model for independently wrapped
-- cryptographic domains. Immutable tenant.key_domain.* events are the source of
-- truth (AN-2); this row is the current, resumable lifecycle snapshot. A missing
-- row deliberately means the tenant is still protected by the deployment KEK.
CREATE TABLE tenant_key_domains (
    tenant_id UUID PRIMARY KEY,
    domain_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    protection_mode TEXT NOT NULL,
    state TEXT NOT NULL,
    wrapper_kind TEXT NOT NULL,
    wrapper_id TEXT NOT NULL,
    wrapped_domain_kek BYTEA NOT NULL,
    operation_id UUID NOT NULL,
    operation_kind TEXT NOT NULL,
    operation_status TEXT NOT NULL,
    migration_stage TEXT NOT NULL DEFAULT '',
    progress_completed BIGINT NOT NULL DEFAULT 0,
    progress_total BIGINT NOT NULL DEFAULT 0,
    progress_cursor TEXT NOT NULL DEFAULT '',
    retryable BOOLEAN NOT NULL DEFAULT FALSE,
    last_error_code TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    legacy_history_exposure TEXT NOT NULL,
    migration_started_at TIMESTAMPTZ,
    migration_completed_at TIMESTAMPTZ,
    sealed_at TIMESTAMPTZ,
    unsealed_at TIMESTAMPTZ,
    last_transition_event_id TEXT NOT NULL,
    last_transition_type TEXT NOT NULL,
    last_transition_actor TEXT NOT NULL DEFAULT '',
    last_transition_at TIMESTAMPTZ NOT NULL,
    last_transition_evidence_refs TEXT[] NOT NULL DEFAULT '{}',
    last_transition_sequence BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT tenant_key_domains_generation_chk
        CHECK (generation > 0),
    CONSTRAINT tenant_key_domains_protection_mode_chk
        CHECK (protection_mode = 'tenant_domain'),
    CONSTRAINT tenant_key_domains_state_chk
        CHECK (state IN (
            'migrating', 'partial', 'unsealed', 'sealing', 'sealed', 'unsealing',
            'wrapper_unavailable', 'wrong_wrapper', 'corrupt'
        )),
    CONSTRAINT tenant_key_domains_wrapper_kind_chk
        CHECK (length(btrim(wrapper_kind)) > 0),
    CONSTRAINT tenant_key_domains_wrapper_id_chk
        CHECK (length(btrim(wrapper_id)) > 0),
    CONSTRAINT tenant_key_domains_wrapped_kek_chk
        CHECK (octet_length(wrapped_domain_kek) > 0),
    CONSTRAINT tenant_key_domains_operation_kind_chk
        CHECK (operation_kind IN ('migrate', 'seal', 'unseal')),
    CONSTRAINT tenant_key_domains_operation_status_chk
        CHECK (operation_status IN ('pending', 'running', 'completed', 'failed')),
    CONSTRAINT tenant_key_domains_progress_chk
        CHECK (
            progress_completed >= 0
            AND progress_total >= 0
            AND progress_completed <= progress_total
        ),
    CONSTRAINT tenant_key_domains_legacy_history_exposure_chk
        CHECK (legacy_history_exposure IN (
            'none', 'hot_history_pending', 'external_archives_possible'
        )),
    CONSTRAINT tenant_key_domains_last_transition_chk
        CHECK (
            length(btrim(last_transition_event_id)) > 0
            AND length(btrim(last_transition_type)) > 0
            AND last_transition_sequence > 0
        )
);

CREATE INDEX tenant_key_domains_tenant_state_idx
    ON tenant_key_domains (tenant_id, state, operation_status);

ALTER TABLE tenant_key_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_key_domains FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_key_domains_isolation
    ON tenant_key_domains
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_key_domains TO trstctl_app;
