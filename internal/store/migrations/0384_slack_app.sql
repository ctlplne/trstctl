-- N8: trstctl's Slack app.
-- slack_installs: the one workspace a tenant installed the app in, its bot
-- token sealed under the tenant's key (the install event carries the same
-- ciphertext, never the token), and the channel approval requests are posted
-- to. Projection of slack.app.installed, slack.app.approval_channel_set and
-- slack.app.uninstalled.
-- slack_user_links: a Slack user a member linked to themselves by typing a
-- one-time code into Slack; projection of slack.user.linked.
-- slack_approval_messages: the message an approval request was posted as and
-- the decision taken from it; projection of slack.approval.posted and
-- slack.approval.decided.
-- slack_one_time_codes: install states and link codes, single-use and kept
-- only as digests; operational like machine_credential_replays, outside the
-- read model.
CREATE TABLE IF NOT EXISTS slack_installs (
    tenant_id             uuid        NOT NULL PRIMARY KEY,
    team_id               text        NOT NULL CHECK (team_id ~ '^T[A-Z0-9]{2,20}$'),
    team_name             text        NOT NULL DEFAULT '' CHECK (length(team_name) <= 200),
    bot_user_id           text        NOT NULL,
    app_id                text        NOT NULL DEFAULT '',
    sealed_bot_token      bytea       NOT NULL,
    approval_channel_id   text        NOT NULL DEFAULT '',
    approval_channel_name text        NOT NULL DEFAULT '' CHECK (length(approval_channel_name) <= 200),
    installed_by          text        NOT NULL,
    installed_at          timestamptz NOT NULL,
    updated_at            timestamptz NOT NULL,
    event_sequence        bigint      NOT NULL CHECK (event_sequence > 0)
);
CREATE UNIQUE INDEX IF NOT EXISTS slack_installs_team_idx ON slack_installs (team_id);

CREATE TABLE IF NOT EXISTS slack_user_links (
    tenant_id      uuid        NOT NULL,
    slack_user_id  text        NOT NULL CHECK (slack_user_id ~ '^[UW][A-Z0-9]{2,20}$'),
    subject        text        NOT NULL CHECK (subject <> ''),
    linked_at      timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, slack_user_id)
);

CREATE TABLE IF NOT EXISTS slack_approval_messages (
    tenant_id           uuid        NOT NULL,
    approval_request_id uuid        NOT NULL,
    channel_id          text        NOT NULL,
    message_ts          text        NOT NULL,
    posted_at           timestamptz NOT NULL,
    decision            text        NOT NULL DEFAULT '' CHECK (decision IN ('', 'approve', 'deny')),
    decided_by          text        NOT NULL DEFAULT '',
    slack_user_id       text        NOT NULL DEFAULT '',
    decided_at          timestamptz,
    event_sequence      bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, approval_request_id)
);

CREATE TABLE IF NOT EXISTS slack_one_time_codes (
    tenant_id   uuid        NOT NULL,
    code_digest text        NOT NULL,
    purpose     text        NOT NULL CHECK (purpose IN ('install', 'link')),
    subject     text        NOT NULL CHECK (subject <> ''),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    PRIMARY KEY (code_digest)
);
CREATE INDEX IF NOT EXISTS slack_one_time_codes_tenant_idx ON slack_one_time_codes (tenant_id, expires_at);

ALTER TABLE slack_installs ENABLE ROW LEVEL SECURITY;
ALTER TABLE slack_installs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS slack_installs_isolation ON slack_installs;
CREATE POLICY slack_installs_isolation ON slack_installs
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
ALTER TABLE slack_user_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE slack_user_links FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS slack_user_links_isolation ON slack_user_links;
CREATE POLICY slack_user_links_isolation ON slack_user_links
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
ALTER TABLE slack_approval_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE slack_approval_messages FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS slack_approval_messages_isolation ON slack_approval_messages;
CREATE POLICY slack_approval_messages_isolation ON slack_approval_messages
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
ALTER TABLE slack_one_time_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE slack_one_time_codes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS slack_one_time_codes_isolation ON slack_one_time_codes;
CREATE POLICY slack_one_time_codes_isolation ON slack_one_time_codes
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON slack_installs, slack_user_links, slack_approval_messages, slack_one_time_codes TO trstctl_app;
