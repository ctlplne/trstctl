-- A261 part 3: auto-approval rules.
--
-- An auto-approval rule approves a privileged access request — a session or a
-- vaulted account's check-out — that matches every condition it sets: the
-- target (by type, ID or folder; a rule always names at least one), the
-- requester's roles, a weekly time window in a time zone, a ticket reference
-- in the reason and a longest lifetime. The approval is recorded as the
-- rule's, with the facts it matched; a request it does not match waits for
-- people. Projected from pam.auto_approval_rule.saved and
-- pam.auto_approval_rule.deleted; a deleted rule stays, marked, for the
-- approvals that name it.
CREATE TABLE IF NOT EXISTS pam_auto_approval_rules (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL,
    name text NOT NULL,
    applies_to text[] NOT NULL,
    target_types text[] NOT NULL,
    target_ids text[] NOT NULL,
    folders text[] NOT NULL,
    requester_roles text[] NOT NULL,
    window_days text[] NOT NULL,
    window_start text NOT NULL,
    window_end text NOT NULL,
    time_zone text NOT NULL,
    ticket_pattern text NOT NULL,
    max_ttl_seconds integer NOT NULL CHECK (max_ttl_seconds > 0),
    enabled boolean NOT NULL,
    revision bigint NOT NULL,
    saved_by text NOT NULL,
    saved_at timestamptz NOT NULL,
    deleted_at timestamptz,
    PRIMARY KEY (tenant_id, id)
);
ALTER TABLE pam_auto_approval_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_auto_approval_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_auto_approval_rules_isolation ON pam_auto_approval_rules
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_auto_approval_rules TO trstctl_app;
