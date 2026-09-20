-- AGID revocation effect ledger (internal/agentid/revoke, AGID-10) — proprietary
-- Enterprise/Provider. Version 910002 is the next value in the AGID extension high
-- band (>= 910000, above the AGID-02 schema at 910001), so it cannot collide with
-- core or succession migration versions. This migration is the ONE durable substrate
-- AGID-10 adds on top of the AGID-02 revocation schema: the per-job recorded-effect
-- ledger that makes the cascade idempotent (claim 16/21 / INV-A8) and the signed
-- per-job completion evidence (claim 16 §7.3 / INV-A9) the AGID-11 terminal gate reads.
--
-- Forward-only by policy (docs/migrations.md, the succession/AGID-02 precedent): the
-- core migration runner records only applied versions and has no down-migration path;
-- recovery is restore-from-backup. Every statement here is additive.

-- ---------------------------------------------------------------------------
-- agent_revocation_effects — exactly one row per (directive, idempotency_key) once a
-- job's effect has been recorded. The (tenant_id, directive_id, idempotency_key)
-- PRIMARY KEY is the AN-5 idempotency substrate: a redelivered job whose effect
-- already landed collides on this key, so a worker retrying at-least-once records AT
-- MOST ONE effect per key (claim 21). The row carries the effect class that was
-- performed, the target credential, the executor identity, the completion timestamp,
-- and the SIGNED completion-evidence bytes (evidence_sig over evidence_body via
-- internal/crypto, AN-3) — the unforgeable per-job proof AGID-11's terminal state
-- rests on (INV-A9). evidence_body is the canonical, replayable evidence document;
-- evidence_sig is the signer's signature over it; evidence_pub is the verifying
-- public key (PKIX/DER) so a relying party or the terminal gate can verify offline.
-- ---------------------------------------------------------------------------
CREATE TABLE agent_revocation_effects (
    tenant_id       uuid   NOT NULL,
    directive_id    text   NOT NULL,          -- companion to agent_revocation_jobs (same tenant)
    idempotency_key text   NOT NULL,          -- the job's AN-5 key: one recorded effect per key (claim 21)
    credential_id   text   NOT NULL,          -- the descendant credential the effect targeted
    effect_class    text   NOT NULL,          -- performed effect: revoke | krl-publish | session-invalidate | notify
    executor        text   NOT NULL DEFAULT '', -- worker/executor identity recorded in the evidence
    completed_at    bigint NOT NULL DEFAULT 0, -- effect completion time (Unix seconds), recorded in evidence
    evidence_body   bytea  NOT NULL,          -- canonical signed completion-evidence document (§7.3)
    evidence_sig    bytea  NOT NULL,          -- signer signature over evidence_body (AN-3, internal/crypto)
    evidence_pub    bytea  NOT NULL,          -- PKIX/DER of the verifying public key (offline-verifiable)
    seq             bigint NOT NULL DEFAULT 0, -- determining ledger sequence of the evidence event
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- One recorded effect per (directive, idempotency_key): a redelivered job whose
    -- effect already landed violates this key and is a no-op (claim 21 / INV-A8).
    PRIMARY KEY (tenant_id, directive_id, idempotency_key)
);

CREATE INDEX agent_revocation_effects_directive
    ON agent_revocation_effects (tenant_id, directive_id);
CREATE INDEX agent_revocation_effects_credential
    ON agent_revocation_effects (tenant_id, credential_id);

ALTER TABLE agent_revocation_effects ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_revocation_effects FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_revocation_effects_isolation ON agent_revocation_effects
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_revocation_effects TO trstctl_app;
