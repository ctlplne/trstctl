-- A122 (owner decision 2026-10-26): an appliance's own reference for a job's key request.
--
-- Cisco ISE names each certificate signing request it generates with an ID of its own choosing, so a renewal cannot find
-- its request again by a name the relay picks. The relay records ISE's ID here, against the job and the attempt that
-- made it, before it asks for a signature; every later attempt of the job is handed the same ID and reuses the request
-- instead of leaving an orphan behind. Confined by RLS; no key material.
CREATE TABLE IF NOT EXISTS agent_job_appliance_references (
    tenant_id        uuid        NOT NULL,
    job_id           bigint      NOT NULL,
    reference        text        NOT NULL CHECK (length(reference) BETWEEN 1 AND 256),
    recorded_attempt integer     NOT NULL CHECK (recorded_attempt > 0),
    recorded_at      timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, job_id)
);
ALTER TABLE agent_job_appliance_references ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_job_appliance_references FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_job_appliance_references_isolation ON agent_job_appliance_references;
CREATE POLICY agent_job_appliance_references_isolation ON agent_job_appliance_references
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_job_appliance_references TO trstctl_app;
