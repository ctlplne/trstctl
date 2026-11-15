-- SPDX-License-Identifier: BUSL-1.1

-- A274L1-L1: each brokered account's recent credential health checks, as its
-- pam.account.health_checked events record them (AN-2: projected from those
-- events). pam_account_health keeps only the latest check, so a sign-in
-- collection explained only the latest check's sign-in and flagged an earlier
-- one made between two runs. The projection keeps the checks of the eight days
-- before an account's newest (a sign-in source looks back at most seven days,
-- plus slack), so the table stays bounded and a rebuild derives the same rows.
CREATE TABLE IF NOT EXISTS pam_account_health_checks (
    tenant_id   uuid        NOT NULL,
    target_type text        NOT NULL,
    target_id   text        NOT NULL,
    checked_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, target_type, target_id, checked_at)
);
ALTER TABLE pam_account_health_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_account_health_checks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pam_account_health_checks_isolation ON pam_account_health_checks;
CREATE POLICY pam_account_health_checks_isolation ON pam_account_health_checks
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_account_health_checks TO trstctl_app;
