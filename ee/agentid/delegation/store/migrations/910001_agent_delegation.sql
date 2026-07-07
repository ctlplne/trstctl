-- AGID delegation store (ee/agentid/delegation/store) — proprietary
-- Enterprise/Provider. Version 910001 is in the reserved extension high band
-- (>= 900000, and above the succession 900001/900002 range so the two extensions
-- never collide) so it cannot collide with core migration versions either. Every
-- table is tenant-scoped: it carries `tenant_id uuid NOT NULL` with ENABLE + FORCE
-- ROW LEVEL SECURITY and an isolation policy keyed on the RLS session GUC
-- (trstctl.tenant_id), so a cross-tenant read/write is denied (AN-1, claim 24 /
-- INV-A8 substrate). These tables are the durable, replayable projection the
-- cascade (AGID-10) and terminal gate (AGID-11) consume; this migration defines the
-- SCHEMA and the read projection only — the cascade job execution, outbox enqueue,
-- terminal transition, and aggregate evidence are written by AGID-10/11.
--
-- Forward-only by policy (docs/migrations.md, mirrored from the succession
-- precedent): the core migration runner records only applied versions and has no
-- down-migration path; recovery is restore-from-backup. Every statement here is
-- additive.

-- ---------------------------------------------------------------------------
-- agent_delegation_records — the durable, queryable delegation tree. One row per
-- delegation record. The parent-hash edge (parent_digest) reconstructs the ordered
-- chain root-to-leaf; a root-anchored record has root_anchor = true and a NULL
-- parent_digest (mirrors ee/agentid/delegation.Record's linkage invariant). The
-- credential's chain is fetched by walking record_digest -> parent_digest.
-- ---------------------------------------------------------------------------
CREATE TABLE agent_delegation_records (
    tenant_id       uuid   NOT NULL,
    record_digest   bytea  NOT NULL,          -- Record.Digest (unique chain node id, per tenant)
    parent_digest   bytea,                     -- parent record digest; NULL iff root_anchor
    root_anchor     boolean NOT NULL DEFAULT false,
    delegator_id    text   NOT NULL,
    delegate_id     text   NOT NULL,
    depth_remaining bigint NOT NULL DEFAULT 0,
    not_before      bigint NOT NULL DEFAULT 0, -- validity window (inclusive Unix seconds)
    not_after       bigint NOT NULL DEFAULT 0,
    encoded         bytea  NOT NULL,           -- opaque canonical-bytes+signature of the record (section 3.1)
    seq             bigint NOT NULL DEFAULT 0, -- determining ledger sequence (watermark ordering)
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, record_digest),
    -- linkage: root-anchored XOR parent-linked (both-or-neither is rejected), so a
    -- dangling record can never be stored (defense in depth beside Record.ValidateLinkage).
    CONSTRAINT agent_delegation_records_linkage
        CHECK (root_anchor = (parent_digest IS NULL))
);

-- Descendant walks and follow-on detection order by seq; index the edge + seq.
CREATE INDEX agent_delegation_records_parent
    ON agent_delegation_records (tenant_id, parent_digest);
CREATE INDEX agent_delegation_records_delegate
    ON agent_delegation_records (tenant_id, delegate_id);
CREATE INDEX agent_delegation_records_seq
    ON agent_delegation_records (tenant_id, seq);

ALTER TABLE agent_delegation_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_delegation_records FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_delegation_records_isolation ON agent_delegation_records
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_delegation_records TO trstctl_app;

-- ---------------------------------------------------------------------------
-- agent_issuances — issued-credential registry. Binds the verified delegation
-- chain (chain_head_digest = the leaf record digest; chain_digest = digest over the
-- whole chain) and the agent-stack digest, with an optional task-envelope digest,
-- a validity window, and a reference to the attestation binding that justified it
-- (AGID-06/07 write; the in-signer verify that precedes issuance is AGID-04).
-- ---------------------------------------------------------------------------
CREATE TABLE agent_issuances (
    tenant_id            uuid   NOT NULL,
    credential_id        text   NOT NULL,      -- issued-credential identifier
    subject_id           text   NOT NULL,      -- the agent subject the credential was issued for
    chain_head_digest    bytea  NOT NULL,      -- leaf delegation-record digest (chain head)
    chain_digest         bytea  NOT NULL,      -- digest over the whole verified chain (INV-A3)
    agent_stack_digest   bytea  NOT NULL,      -- agent-stack representation digest (INV-A3)
    task_envelope_digest bytea,                 -- optional bound task-envelope digest (INV-A4)
    not_before           bigint NOT NULL DEFAULT 0,
    not_after            bigint NOT NULL DEFAULT 0,
    attestation_ref      bytea,                 -- attestation binding that justified this issuance (INV-A6)
    seq                  bigint NOT NULL DEFAULT 0,
    created_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, credential_id)
);

CREATE INDEX agent_issuances_subject
    ON agent_issuances (tenant_id, subject_id);
CREATE INDEX agent_issuances_chain_head
    ON agent_issuances (tenant_id, chain_head_digest);

ALTER TABLE agent_issuances ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_issuances FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_issuances_isolation ON agent_issuances
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_issuances TO trstctl_app;

-- ---------------------------------------------------------------------------
-- agent_attestation_bindings — verified attestation evidence bound to the issuance
-- it justified (section 4.2; the replay-refusal in AGID-07 reads this to refuse a
-- second issuance presenting the same evidence — INV-A6). The evidence_digest is
-- unique per tenant so the same attestation cannot justify two issuances.
-- ---------------------------------------------------------------------------
CREATE TABLE agent_attestation_bindings (
    tenant_id       uuid   NOT NULL,
    binding_id      text   NOT NULL,
    credential_id   text   NOT NULL,           -- the issuance this attestation justified
    evidence_digest bytea  NOT NULL,           -- digest of the verified attestation evidence
    attestation_class text NOT NULL DEFAULT '', -- verified attestation class (min-class gate, INV-A6)
    verified_at     bigint NOT NULL DEFAULT 0,
    seq             bigint NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, binding_id)
);

-- One issuance per attestation evidence: a replayed attestation is rejected by the
-- unique constraint (INV-A6 replay-refused substrate).
CREATE UNIQUE INDEX agent_attestation_bindings_evidence_uq
    ON agent_attestation_bindings (tenant_id, evidence_digest);
CREATE INDEX agent_attestation_bindings_credential
    ON agent_attestation_bindings (tenant_id, credential_id);

ALTER TABLE agent_attestation_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_attestation_bindings FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_attestation_bindings_isolation ON agent_attestation_bindings
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_attestation_bindings TO trstctl_app;

-- ---------------------------------------------------------------------------
-- agent_refusal_records — signed refusal artifacts (AGID-04 writes; section 3.4).
-- The signer appends one when any in-custody check fails: no private-key operation
-- happened, and this names the failed check with the signer's signature over the
-- refusal (INV-A1 signed-refusal substrate).
-- ---------------------------------------------------------------------------
CREATE TABLE agent_refusal_records (
    tenant_id      uuid   NOT NULL,
    refusal_id     text   NOT NULL,
    subject_id     text   NOT NULL,
    failed_check   text   NOT NULL,            -- the named check that failed
    request_digest bytea,                       -- digest of the refused issuance request
    signature      bytea  NOT NULL,            -- signer signature over the refusal artifact
    seq            bigint NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, refusal_id)
);

CREATE INDEX agent_refusal_records_subject
    ON agent_refusal_records (tenant_id, subject_id);

ALTER TABLE agent_refusal_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_refusal_records FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_refusal_records_isolation ON agent_refusal_records
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_refusal_records TO trstctl_app;

-- ---------------------------------------------------------------------------
-- agent_revocation_directives — a revocation directive against a subject and the
-- determining watermark (the sequence of the ledger prefix the descendant set was
-- computed over). AGID-10/11 write the cascade; this card defines the SCHEMA + the
-- read projection only. terminal is advanced by AGID-11 when every enqueued and
-- follow-on job has signed completion evidence (INV-A9).
-- ---------------------------------------------------------------------------
CREATE TABLE agent_revocation_directives (
    tenant_id       uuid   NOT NULL,
    directive_id    text   NOT NULL,
    subject_id      text   NOT NULL,
    reason          text   NOT NULL DEFAULT '',
    watermark       bigint NOT NULL,           -- ledger sequence the descendant set was determined as-of (INV-A8)
    terminal        boolean NOT NULL DEFAULT false, -- true iff terminal revoked (all jobs evidenced; AGID-11)
    seq             bigint NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, directive_id)
);

CREATE INDEX agent_revocation_directives_subject
    ON agent_revocation_directives (tenant_id, subject_id);

ALTER TABLE agent_revocation_directives ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_revocation_directives FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_revocation_directives_isolation ON agent_revocation_directives
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_revocation_directives TO trstctl_app;

-- ---------------------------------------------------------------------------
-- agent_revocation_jobs — one row per descendant credential in the cascade, with
-- the idempotency key (at-most-one recorded effect per key, INV-A8) and a
-- completion-evidence reference (signed per-job completion evidence, written by
-- AGID-10/11). This card defines the SCHEMA + the read projection; the job
-- execution / outbox enqueue is AGID-10. The (tenant_id, directive_id,
-- idempotency_key) primary key makes a redelivered job a no-op.
-- ---------------------------------------------------------------------------
CREATE TABLE agent_revocation_jobs (
    tenant_id        uuid   NOT NULL,
    directive_id     text   NOT NULL,          -- companion to agent_revocation_directives (same tenant)
    idempotency_key  text   NOT NULL,          -- one recorded effect per key (INV-A8 idempotent)
    credential_id    text   NOT NULL,          -- the descendant credential this job revokes
    follow_on        boolean NOT NULL DEFAULT false, -- true iff generated for a record committed after the watermark (INV-A8)
    completion_ref   bytea,                      -- reference to signed per-job completion evidence (AGID-10/11)
    seq              bigint NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, directive_id, idempotency_key)
);

CREATE INDEX agent_revocation_jobs_directive
    ON agent_revocation_jobs (tenant_id, directive_id);
CREATE INDEX agent_revocation_jobs_credential
    ON agent_revocation_jobs (tenant_id, credential_id);

ALTER TABLE agent_revocation_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_revocation_jobs FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_revocation_jobs_isolation ON agent_revocation_jobs
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_revocation_jobs TO trstctl_app;
