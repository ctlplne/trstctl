-- A5: the dispatch ledger for staged agent upgrades.
--
-- Before this table the campaign sweep OBSERVED versions and gated rings, but
-- nothing moved an agent onto the target version: an operator pushed builds out
-- of band and the campaign watched them arrive. A ring outcome must be computed
-- against WHO WAS TOLD TO UPGRADE, not against whoever happens to sit in the
-- ring when the sweep looks — an agent assigned to the canary after dispatch
-- must not be scored silent for a job it was never given.
--
-- One row per (campaign, round, agent). round increments every time a ring is
-- (re)entered: a resume after a halt re-dispatches the ring, and the old
-- round's rows must stop counting — a receipt from the failed round scored
-- against the retry would halt a rollout on evidence the operator already
-- acted on.
--
-- job_key is the outbox idempotency key of the dispatched agent.upgrade job.
-- The join to receipts goes dispatch -> outbox (by key) -> agent_job_receipts
-- (by job id), so the ledger never duplicates receipt state and cannot drift
-- from it.
--
-- Pure projection of agent.upgrade.ring.dispatched (AN-2): rebuilt by replay,
-- classified RecoveredByLogRebuild via ReadModelTables.
CREATE TABLE IF NOT EXISTS agent_upgrade_dispatches (
    tenant_id     uuid        NOT NULL,
    campaign_id   uuid        NOT NULL,
    round         integer     NOT NULL,
    ring          text        NOT NULL,
    agent_id      uuid        NOT NULL,
    job_key       text        NOT NULL,
    dispatched_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, campaign_id, round, agent_id)
);

ALTER TABLE agent_upgrade_dispatches ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_upgrade_dispatches FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS agent_upgrade_dispatches_tenant_isolation ON agent_upgrade_dispatches;
CREATE POLICY agent_upgrade_dispatches_tenant_isolation ON agent_upgrade_dispatches
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON agent_upgrade_dispatches TO trstctl_app;

COMMENT ON TABLE agent_upgrade_dispatches IS
    'Per-round agent.upgrade job dispatches for staged rollouts (epic A5). Projection of agent.upgrade.ring.dispatched; ring outcomes are computed against these rows joined to agent_job_receipts.';
