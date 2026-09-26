-- A reclaimed lease must not erase who received the original work. These are
-- operational outbox bindings, committed in the same transaction as each claim;
-- they authorize recording completion, never renewed access to the job.
CREATE TABLE agent_job_attempt_bindings (
    tenant_id uuid NOT NULL,
    job_id bigint NOT NULL,
    attempt integer NOT NULL CHECK (attempt > 0),
    agent_id uuid NOT NULL,
    destination text NOT NULL,
    PRIMARY KEY (tenant_id, job_id, attempt)
);
ALTER TABLE agent_job_attempt_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_job_attempt_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_job_attempt_bindings_isolation ON agent_job_attempt_bindings
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_job_attempt_bindings TO trstctl_app;

-- Upgrade only identities still present in the old ledger, including expired
-- leases not yet swept. Earlier or already-reclaimed holders cannot be inferred.
INSERT INTO agent_job_attempt_bindings (tenant_id, job_id, attempt, agent_id, destination)
SELECT tenant_id, id, claim_attempts, claimed_by_agent_id, destination
FROM outbox
WHERE claimed_by_agent_id IS NOT NULL AND claim_attempts > 0;
