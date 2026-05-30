-- Certificate Transparency monitoring (F17): the durable state the CT monitor
-- needs between runs. ct_watched_domains is the set of domains a tenant watches
-- for unexpected issuance; ct_log_checkpoints records how far each CT log has
-- been read (the next tree index to fetch) so polling resumes where it left off
-- and never re-alerts on already-seen entries. Per AN-1 every row carries
-- tenant_id and is confined by row-level security; a checkpoint is per
-- (tenant, log).

CREATE TABLE ct_watched_domains (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL,
    domain     text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, domain)
);

ALTER TABLE ct_watched_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE ct_watched_domains FORCE ROW LEVEL SECURITY;

CREATE POLICY ct_watched_domains_isolation ON ct_watched_domains
    USING (tenant_id = current_setting('certctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('certctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON ct_watched_domains TO certctl_app;

CREATE TABLE ct_log_checkpoints (
    tenant_id  uuid NOT NULL,
    log_url    text NOT NULL,
    next_index bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, log_url)
);

ALTER TABLE ct_log_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE ct_log_checkpoints FORCE ROW LEVEL SECURITY;

CREATE POLICY ct_log_checkpoints_isolation ON ct_log_checkpoints
    USING (tenant_id = current_setting('certctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('certctl.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON ct_log_checkpoints TO certctl_app;
