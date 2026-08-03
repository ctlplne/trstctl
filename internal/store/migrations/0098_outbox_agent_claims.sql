-- The outbox becomes the agent job ledger (epic A1).
--
-- Work that touches a customer's estate — deploying to a host, probing an
-- endpoint, scanning a segment, driving an appliance — is decided in the control
-- plane and executed in the customer's environment by an agent. The control
-- plane never reaches into a host, so the agent has to come and take the work.
--
-- Nothing about the ledger changes to allow that. An entry is still committed in
-- the same transaction as the state change that caused it (AN-6), still carries
-- an idempotency key (AN-5), and is still at-least-once. What changes is the
-- consumer: instead of a control-plane dispatcher executing the entry, an agent
-- claims it over the channel it opened, executes locally, and reports back.
--
-- A claim is a lease, not an assignment. An agent that dies mid-job stops
-- extending its lease and the entry returns to the queue rather than being stuck
-- to a machine that is gone. claim_attempts counts how many times an entry has
-- been claimed, so a job that keeps being taken and dropped is visible rather
-- than silently cycling.

ALTER TABLE outbox
    -- The agent holding the current lease. NULL means unclaimed and claimable.
    ADD COLUMN claimed_by_agent_id uuid,
    -- When the lease lapses. A claim past this instant is reclaimable by anyone.
    ADD COLUMN claim_expires_at timestamptz,
    -- How many times this entry has been claimed, ever. A high count with no
    -- delivery is the signature of an agent taking work it cannot finish.
    ADD COLUMN claim_attempts integer NOT NULL DEFAULT 0
        CHECK (claim_attempts >= 0),
    -- When the claiming agent reported a terminal result, so the ledger can tell
    -- "nobody has taken this" from "somebody took it and finished".
    ADD COLUMN claim_completed_at timestamptz,
    -- Composite FK to agents is deliberately absent: an entry outlives the agent
    -- that claimed it, and offboarding an agent must not cascade away the
    -- evidence of what it was asked to do.
    ADD CONSTRAINT outbox_claim_lease_present
        CHECK ((claimed_by_agent_id IS NULL) = (claim_expires_at IS NULL));
