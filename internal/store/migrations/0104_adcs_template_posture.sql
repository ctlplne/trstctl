-- AD CS certificate template posture (epic F1).
--
-- A Windows PKI's real attack surface is its template list, and the information
-- lives in a directory a hosted control plane cannot reach. An in-domain relay
-- reads it; this is where what it found becomes something an operator can look
-- at tomorrow rather than only in the job report from the run that found it.
--
-- One row per (tenant, domain, template). The domain is part of the key because
-- a forest holds several, and a template named "User" in one is not the template
-- named "User" in another — merging them would silently hide a dangerous
-- template behind a safe namesake.
--
-- What is stored is what the directory said plus the verdicts derived from it.
-- No credential, no security descriptor bytes, no directory bind identity: the
-- relay reads with an operator's credential and reports findings, and none of
-- that credential's material belongs here.
--
-- findings is jsonb because the finding set is a vocabulary that grows as the
-- analysis learns new dangerous combinations, and a column per check would mean
-- a migration every time somebody notices one. The severity and count columns
-- are extracted alongside so the console can sort and filter without unpacking
-- json for every row.
CREATE TABLE adcs_template_posture (
    tenant_id        uuid        NOT NULL,
    domain           text        NOT NULL,
    template         text        NOT NULL,
    display_name     text        NOT NULL DEFAULT '',
    schema_version   integer     NOT NULL DEFAULT 0,
    published_by     text[]      NOT NULL DEFAULT '{}',
    -- The verdict summary. worst_severity is '' when a template has no findings
    -- at all, which is a real and common state and must not sort as unknown.
    worst_severity   text        NOT NULL DEFAULT '',
    finding_count    integer     NOT NULL DEFAULT 0,
    findings         jsonb       NOT NULL DEFAULT '[]'::jsonb,
    -- Where and when this came from. An operator looking at a dangerous template
    -- needs to know whether they are reading yesterday's answer.
    observed_by      text        NOT NULL DEFAULT '',
    observed_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain, template)
);

ALTER TABLE adcs_template_posture ENABLE ROW LEVEL SECURITY;
ALTER TABLE adcs_template_posture FORCE ROW LEVEL SECURITY;

CREATE POLICY adcs_template_posture_isolation ON adcs_template_posture
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- The console's default view is "what is dangerous, worst first", so that is
-- what the index serves.
CREATE INDEX adcs_template_posture_severity_idx
    ON adcs_template_posture (tenant_id, worst_severity, template);

-- The severity vocabulary is closed at the database, like every other status
-- this system stores: nothing may write a severity the console has no meaning
-- for, whatever path it arrives by.
ALTER TABLE adcs_template_posture
    ADD CONSTRAINT adcs_template_posture_severity_known
    CHECK (worst_severity IN ('', 'medium', 'high', 'critical'));

GRANT SELECT, INSERT, UPDATE, DELETE ON adcs_template_posture TO trstctl_app;

COMMENT ON TABLE adcs_template_posture IS
    'AD CS certificate template posture observed by an in-domain relay (epic F1). Verdicts and directory attributes only — never credentials or security-descriptor bytes.';
