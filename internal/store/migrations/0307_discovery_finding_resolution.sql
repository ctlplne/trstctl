-- SPDX-License-Identifier: BUSL-1.1
-- A106: resolution workflows for posture findings. An investigation names an
-- assignee and a due date, a remediation the evidence of its fix, and an
-- accepted risk the time its acceptance expires. Every column is projected
-- from discovery.finding.triage_changed; empty and NULL are the values every
-- existing row keeps. The expiry sweep reads accepted_risk rows through the
-- existing (tenant_id, triage_status, id) index.
ALTER TABLE discovery_findings
    ADD COLUMN triage_assignee text NOT NULL DEFAULT '',
    ADD COLUMN triage_due_at timestamptz,
    ADD COLUMN triage_evidence_ref text NOT NULL DEFAULT '',
    ADD COLUMN risk_accepted_until timestamptz;
