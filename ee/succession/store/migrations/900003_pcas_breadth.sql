-- PCAS production breadth store (delegation, recovery, federation, KEM rewrap,
-- checkpoints, monitors, and issuer/staple state). These tables are serving
-- projections or operator policy rows fed by events/outbox work; every row is
-- tenant-scoped and protected by forced RLS (AN-1).

CREATE TABLE pcas_delegation_scope (
    tenant_id         uuid   NOT NULL,
    scope_id          text   NOT NULL,
    parent_scope_id   text   NOT NULL DEFAULT '',
    epoch_floor       bigint NOT NULL DEFAULT 0,
    updated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, scope_id)
);

CREATE TABLE pcas_recovery_policy (
    tenant_id          uuid   NOT NULL,
    identity_id        text   NOT NULL,
    threshold          integer NOT NULL,
    roster_json        jsonb  NOT NULL DEFAULT '[]'::jsonb,
    trust_root_der     bytea  NOT NULL DEFAULT ''::bytea,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, identity_id)
);

CREATE TABLE pcas_federation_bridge (
    tenant_id              uuid   NOT NULL,
    foreign_deployment_id  text   NOT NULL,
    identity_id            text   NOT NULL,
    foreign_trust_root_der bytea  NOT NULL DEFAULT ''::bytea,
    local_base_epoch       bigint NOT NULL DEFAULT 0,
    bridge_json            jsonb  NOT NULL DEFAULT '{}'::jsonb,
    updated_at             timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, foreign_deployment_id, identity_id)
);

CREATE TABLE pcas_federation_quarantine (
    tenant_id              uuid   NOT NULL,
    foreign_deployment_id  text   NOT NULL,
    identity_id            text   NOT NULL,
    reason                 text   NOT NULL,
    proof_json             jsonb  NOT NULL DEFAULT '{}'::jsonb,
    detected_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, foreign_deployment_id, identity_id, detected_at)
);

CREATE TABLE pcas_rewrap_job (
    tenant_id          uuid   NOT NULL,
    job_id             text   NOT NULL,
    identity_id        text   NOT NULL,
    predecessor_epoch  bigint NOT NULL,
    stage              text   NOT NULL,
    total_stages       integer NOT NULL DEFAULT 1,
    completed_stages   integer NOT NULL DEFAULT 0,
    status             text   NOT NULL,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, job_id, stage)
);

CREATE INDEX pcas_rewrap_job_identity_idx
    ON pcas_rewrap_job (tenant_id, identity_id, predecessor_epoch);

CREATE TABLE pcas_epoch_checkpoint (
    tenant_id      uuid   NOT NULL,
    identity_id    text   NOT NULL,
    epoch          bigint NOT NULL,
    log_tree_size  bigint NOT NULL,
    log_root       bytea  NOT NULL,
    signature      bytea  NOT NULL,
    checkpoint_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    issued_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, identity_id, epoch)
);

CREATE TABLE pcas_misissuance (
    tenant_id        uuid   NOT NULL,
    identity_id      text   NOT NULL,
    epoch            bigint NOT NULL,
    record_a_digest  bytea  NOT NULL,
    record_b_digest  bytea  NOT NULL,
    signer_a         text   NOT NULL,
    signer_b         text   NOT NULL,
    proof_json       jsonb  NOT NULL DEFAULT '{}'::jsonb,
    detected_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, identity_id, epoch, record_a_digest, record_b_digest)
);

CREATE TABLE pcas_issuer_authority (
    tenant_id        uuid   NOT NULL,
    issuer_id        text   NOT NULL,
    identity_id      text   NOT NULL,
    current_epoch    bigint NOT NULL,
    ca_key_handle    text   NOT NULL DEFAULT '',
    ca_cert_der      bytea  NOT NULL DEFAULT ''::bytea,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, issuer_id)
);

CREATE TABLE pcas_retirement_policy (
    tenant_id               uuid   NOT NULL,
    identity_id             text   NOT NULL,
    predecessor_epoch       bigint NOT NULL,
    threshold               integer NOT NULL,
    roster_json             jsonb  NOT NULL DEFAULT '[]'::jsonb,
    validity_window_seconds bigint NOT NULL DEFAULT 0,
    predecessor_handle      text   NOT NULL DEFAULT '',
    status                  text   NOT NULL DEFAULT 'active',
    updated_at              timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, identity_id, predecessor_epoch)
);

ALTER TABLE pcas_delegation_scope ENABLE ROW LEVEL SECURITY;
ALTER TABLE pcas_delegation_scope FORCE ROW LEVEL SECURITY;
CREATE POLICY pcas_delegation_scope_isolation ON pcas_delegation_scope
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

ALTER TABLE pcas_recovery_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE pcas_recovery_policy FORCE ROW LEVEL SECURITY;
CREATE POLICY pcas_recovery_policy_isolation ON pcas_recovery_policy
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

ALTER TABLE pcas_federation_bridge ENABLE ROW LEVEL SECURITY;
ALTER TABLE pcas_federation_bridge FORCE ROW LEVEL SECURITY;
CREATE POLICY pcas_federation_bridge_isolation ON pcas_federation_bridge
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

ALTER TABLE pcas_federation_quarantine ENABLE ROW LEVEL SECURITY;
ALTER TABLE pcas_federation_quarantine FORCE ROW LEVEL SECURITY;
CREATE POLICY pcas_federation_quarantine_isolation ON pcas_federation_quarantine
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

ALTER TABLE pcas_rewrap_job ENABLE ROW LEVEL SECURITY;
ALTER TABLE pcas_rewrap_job FORCE ROW LEVEL SECURITY;
CREATE POLICY pcas_rewrap_job_isolation ON pcas_rewrap_job
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

ALTER TABLE pcas_epoch_checkpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE pcas_epoch_checkpoint FORCE ROW LEVEL SECURITY;
CREATE POLICY pcas_epoch_checkpoint_isolation ON pcas_epoch_checkpoint
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

ALTER TABLE pcas_misissuance ENABLE ROW LEVEL SECURITY;
ALTER TABLE pcas_misissuance FORCE ROW LEVEL SECURITY;
CREATE POLICY pcas_misissuance_isolation ON pcas_misissuance
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

ALTER TABLE pcas_issuer_authority ENABLE ROW LEVEL SECURITY;
ALTER TABLE pcas_issuer_authority FORCE ROW LEVEL SECURITY;
CREATE POLICY pcas_issuer_authority_isolation ON pcas_issuer_authority
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

ALTER TABLE pcas_retirement_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE pcas_retirement_policy FORCE ROW LEVEL SECURITY;
CREATE POLICY pcas_retirement_policy_isolation ON pcas_retirement_policy
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON pcas_delegation_scope      TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pcas_recovery_policy       TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pcas_federation_bridge     TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pcas_federation_quarantine TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pcas_rewrap_job            TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pcas_epoch_checkpoint      TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pcas_misissuance           TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pcas_issuer_authority      TO trstctl_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pcas_retirement_policy     TO trstctl_app;
