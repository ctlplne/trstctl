-- The signed job receipt ledger (epic A1).
--
-- A receipt is checked at report time and would otherwise be checked and
-- discarded, which gives an auditor nothing: they would have to take the
-- server's word that something once verified. The event log keeps the receipt
-- itself; this is the read model that lets an operator see the state of the
-- fabric without replaying it — how many receipts verified, how many were
-- refused, and what the last refusal said.
--
-- Refusals are the reason this table exists. A receipt that verifies is
-- unremarkable; a receipt that does not means somebody's agent believes it did
-- work the ledger will not record, and the two ways that happens — a clock that
-- drifted and a key that is not the one the certificate names — need to be
-- distinguishable at a glance rather than by reading a stream.
--
-- What is stored is the statement, the signature, and the fingerprint of the
-- certificate to verify against. All three are public material by construction:
-- a statement carries a tenant, an agent name, a job id and digests, never a
-- credential, and a signature is not a secret. The detail text a report carried
-- is NOT here — it lives on the job row, where the existing closed-set
-- last_error discipline governs it, and the statement's digest is what binds
-- the two.
CREATE TABLE agent_job_receipts (
    tenant_id           uuid        NOT NULL,
    job_id              bigint      NOT NULL,
    -- attempt is part of the key because a job claimed twice produces two
    -- receipts, and collapsing them would hide the case that matters: one
    -- attempt reported failure and a later one reported success.
    attempt             integer     NOT NULL DEFAULT 0,
    agent               text        NOT NULL DEFAULT '',
    kind                text        NOT NULL DEFAULT '',
    outcome             text        NOT NULL DEFAULT '',
    -- state is the verdict on the receipt, not on the work. 'verified' means the
    -- agent's signature checked out; 'rejected' means it did not and the report
    -- was refused.
    state               text        NOT NULL,
    -- reason is set only for a rejection, and only from the closed set the
    -- server writes — never from anything the agent sent.
    reason              text        NOT NULL DEFAULT '',
    signer_fingerprint  text        NOT NULL DEFAULT '',
    statement           text        NOT NULL DEFAULT '',
    signature           text        NOT NULL DEFAULT '',
    observed_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, job_id, attempt, state)
);

ALTER TABLE agent_job_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_job_receipts FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_job_receipts_isolation ON agent_job_receipts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- The operations panel asks two questions: how many of each state, and what was
-- the most recent rejection. Both are served by ordering within a state.
CREATE INDEX agent_job_receipts_state_idx
    ON agent_job_receipts (tenant_id, state, observed_at DESC);

-- The state vocabulary is closed at the database like every other status this
-- system stores, so nothing can write a third state the console has no meaning
-- for, whatever path it arrives by.
ALTER TABLE agent_job_receipts
    ADD CONSTRAINT agent_job_receipts_state_known
    CHECK (state IN ('verified', 'rejected'));

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_job_receipts TO trstctl_app;

COMMENT ON TABLE agent_job_receipts IS
    'Signed agent job receipts and refusals (epic A1). Statements, signatures and signer fingerprints only — all public material; the report detail text stays on the job row.';
