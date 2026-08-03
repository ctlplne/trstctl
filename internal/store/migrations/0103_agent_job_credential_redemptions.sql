-- Just-in-time credential redemptions for agent-executed jobs (epic A3).
--
-- A relay job carries REFERENCES, never credentials: the sealed deploy payload
-- and its secret:// names stay in the brain. At execution time the relay calls
-- RedeemJobCredential over the same mTLS channel it claimed on, and the control
-- plane resolves the references, hands the material over the encrypted channel,
-- and records that it did so. The relay holds the bytes in locked memory for
-- one attempt and wipes them. The brain never ships standing credentials.
--
-- This table is the single-use gate AND the audit trail, in one atomic step:
-- redemption is an INSERT ... ON CONFLICT DO NOTHING keyed by
-- (tenant_id, job_id, attempt), performed only if the caller currently holds
-- the job's claim lease. One row per attempt, ever. A replay — same agent
-- asking twice, a second agent racing after a lease steal, a stale attempt
-- number — inserts nothing, returns nothing, and the caller gets a refusal
-- with no way to distinguish why.
--
-- Why not reuse an existing single-use primitive:
--   * secret_shares consume by DELETE ... RETURNING — race-safe, but leaves no
--     evidence row, and a redemption must be auditable per job.
--   * agent_bootstrap_tokens redeem by conditional UPDATE on a pre-minted row —
--     the right predicate, but it would mint a row per job at enqueue, coupling
--     credential custody to the outbox and creating rows for jobs the control
--     plane executes itself.
--   * idempotency_keys deliberately REPLAY results (AN-5) and are GC-swept, so
--     a marker there would re-serve the credential and then expire back into
--     redeemability. The opposite of single-use.
--
-- expires_at is bound to the claim lease at redemption time, never chosen
-- independently: a redeemed credential must not outlive the claim, because a
-- lapsed lease makes the job claimable by another agent while the first still
-- holds live material.
--
-- binding is a non-secret SHA-256 digest tying the redemption to the exact
-- (tenant, job, agent, attempt, destination, idempotency key) it authorized —
-- readable evidence that cannot be repointed at different work after the fact.
--
-- Per AN-1 the table carries tenant_id and is confined by row-level security;
-- redemption always runs under the tenant derived from the agent's certificate.
CREATE TABLE agent_job_credential_redemptions (
    tenant_id   uuid        NOT NULL,
    job_id      bigint      NOT NULL,
    attempt     integer     NOT NULL,
    agent_id    uuid        NOT NULL,
    binding     bytea       NOT NULL,
    audit_ref   uuid        NOT NULL DEFAULT gen_random_uuid(),
    redeemed_at timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, job_id, attempt)
);

ALTER TABLE agent_job_credential_redemptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_job_credential_redemptions FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_job_credential_redemptions_isolation ON agent_job_credential_redemptions
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- The audit read-back path resolves a redemption by its public reference.
-- online-safe: the table is created in this migration, so a plain unique index
-- builds against zero rows and holds no meaningful lock.
CREATE UNIQUE INDEX agent_job_credential_redemptions_audit_ref_idx
    ON agent_job_credential_redemptions (tenant_id, audit_ref);

-- SELECT and INSERT are what the redemption path itself needs: the ledger is
-- append-only, and no code path updates a row (a redemption's whole meaning is
-- that it happened once). DELETE is granted solely so tenant offboarding can
-- erase a departing tenant's history along with everything else it owns —
-- TestEveryTenantTableCoveredByOffboard enforces that no tenant-scoped table is
-- left behind. There is deliberately no UPDATE: nothing may rewrite a
-- redemption after the fact.
GRANT SELECT, INSERT, DELETE ON agent_job_credential_redemptions TO trstctl_app;
