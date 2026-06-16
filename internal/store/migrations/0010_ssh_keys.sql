-- SSH key inventory (F42): the catalog of every discovered SSH key — host keys,
-- user keys, authorized_keys grants, known_hosts trust, and sshd trusted CAs —
-- the SSH half of the discovery inventory. Like certificates, a key is
-- inventoried once per tenant (UNIQUE on its fingerprint) and re-discovering
-- refreshes its row. Per AN-1 each row carries tenant_id and is confined by
-- row-level security.
--
-- standing_access marks a grant that confers persistent login (an
-- authorized_keys entry); orphaned marks an unattributable grant nobody can
-- account for. These are the signals folded into the credential graph (F21) and
-- risk scoring (F19).
CREATE TABLE ssh_keys (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL,
    fingerprint     text NOT NULL,
    key_type        text NOT NULL DEFAULT '',
    comment         text NOT NULL DEFAULT '',
    source          text NOT NULL DEFAULT '',
    location        text NOT NULL DEFAULT '',
    standing_access boolean NOT NULL DEFAULT false,
    orphaned        boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, fingerprint)
);

ALTER TABLE ssh_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssh_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY ssh_keys_isolation ON ssh_keys
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- "Which standing-access / orphaned grants exist" is a primary risk query.
CREATE INDEX ssh_keys_standing_idx ON ssh_keys (tenant_id, standing_access, orphaned);

GRANT SELECT, INSERT, UPDATE, DELETE ON ssh_keys TO trstctl_app;
