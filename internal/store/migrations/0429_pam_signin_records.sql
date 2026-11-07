-- SPDX-License-Identifier: BUSL-1.1
-- A274: the sign-ins bypass detection read for a provider's managed accounts
-- (metadata only) and what explained each, kept under the deployment's
-- retention. One row per sign-in on a provider's target.
CREATE TABLE pam_signin_records (
 tenant_id uuid NOT NULL,
 provider_id text NOT NULL,
 fingerprint text NOT NULL,
 account text NOT NULL,
 signed_in_at timestamptz NOT NULL,
 earliest_at timestamptz,
 source text NOT NULL DEFAULT '',
 method text NOT NULL DEFAULT '',
 key_id text NOT NULL DEFAULT '',
 ref text NOT NULL DEFAULT '',
 explained_by text NOT NULL DEFAULT '',
 explained_ref text NOT NULL DEFAULT '',
 collector text NOT NULL DEFAULT '',
 first_run_id text NOT NULL,
 last_seen_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id, provider_id, fingerprint)
);
CREATE INDEX pam_signin_records_time_idx ON pam_signin_records(tenant_id, signed_in_at DESC, fingerprint);
CREATE INDEX pam_signin_records_retention_idx ON pam_signin_records(signed_in_at);
ALTER TABLE pam_signin_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_signin_records FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_signin_records_isolation ON pam_signin_records
 USING(tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK(tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON pam_signin_records TO trstctl_app;
