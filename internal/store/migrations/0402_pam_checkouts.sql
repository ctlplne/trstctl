-- A261 part 2: check-outs of vaulted accounts. A check-out reveals a vaulted
-- account's current credential once to its requester after independent
-- review; checking it in, or its deadline passing, rotates the account so the
-- revealed credential stops working. Projected from pam.checkout.revealed and
-- pam.checkout.ended; the credential itself is never stored here.
CREATE TABLE IF NOT EXISTS pam_checkouts (
    tenant_id uuid NOT NULL,
    request_id uuid NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    provider_id text NOT NULL,
    account_secret text NOT NULL,
    secret_version integer NOT NULL,
    requested_by text NOT NULL,
    reason text NOT NULL,
    approval_request_id uuid NOT NULL,
    revealed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('revealed', 'checked_in', 'expired')),
    ended_at timestamptz,
    ended_by text NOT NULL DEFAULT '',
    rotation_command_id text NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, request_id)
);
CREATE INDEX IF NOT EXISTS pam_checkouts_due_idx ON pam_checkouts (expires_at) WHERE status = 'revealed';
ALTER TABLE pam_checkouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_checkouts FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_checkouts_isolation ON pam_checkouts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_checkouts TO trstctl_app;
