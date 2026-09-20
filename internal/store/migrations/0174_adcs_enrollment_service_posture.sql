-- SPDX-License-Identifier: BUSL-1.1

-- AUD-37 / F3: normalized, event-derived CA and IIS enrollment-service posture.
-- The relay keeps response bodies, cookies, raw certutil output, and credentials
-- in the estate. This projection stores only the closed facts needed to explain
-- the posture verdict and is replaced atomically with the template view.
CREATE TABLE adcs_enrollment_service_posture (
    tenant_id                 uuid        NOT NULL,
    domain                    text        NOT NULL,
    service                   text        NOT NULL,
    dns_name                  text        NOT NULL DEFAULT '',
    enrollment_web_services  text[]      NOT NULL DEFAULT '{}',
    agent_restriction_state  text        NOT NULL,
    agent_restriction_source text        NOT NULL,
    worst_severity            text        NOT NULL DEFAULT '',
    finding_count             integer     NOT NULL DEFAULT 0,
    findings                  jsonb       NOT NULL DEFAULT '[]'::jsonb,
    observed_service          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    observed_by               text        NOT NULL,
    observed_at               timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, domain, service),
    CONSTRAINT adcs_enrollment_service_restriction_state_known
        CHECK (agent_restriction_state IN ('enabled', 'disabled', 'unobserved')),
    CONSTRAINT adcs_enrollment_service_severity_known
        CHECK (worst_severity IN ('', 'medium', 'high', 'critical')),
    CONSTRAINT adcs_enrollment_service_findings_array
        CHECK (jsonb_typeof(findings) = 'array'),
    CONSTRAINT adcs_enrollment_service_observation_object
        CHECK (jsonb_typeof(observed_service) = 'object')
);

ALTER TABLE adcs_enrollment_service_posture ENABLE ROW LEVEL SECURITY;
ALTER TABLE adcs_enrollment_service_posture FORCE ROW LEVEL SECURITY;
CREATE POLICY adcs_enrollment_service_posture_isolation ON adcs_enrollment_service_posture
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX adcs_enrollment_service_posture_severity_idx
    ON adcs_enrollment_service_posture (tenant_id, worst_severity, domain, service);

GRANT SELECT, INSERT, UPDATE, DELETE ON adcs_enrollment_service_posture TO trstctl_app;

COMMENT ON TABLE adcs_enrollment_service_posture IS
    'Event-derived AD CS enrollment-service posture: normalized LDAP, HTTP probe, and CA restriction facts; never raw responses or credentials.';
