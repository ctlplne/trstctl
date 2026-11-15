-- SPDX-License-Identifier: BUSL-1.1

-- G1-L6: the approval a PAM session's activation consumed, as its
-- pam.session.activation_requested event names it (AN-2: projected from that
-- event). A session whose started event predates the session's own link
-- (migration 0355) reads its approval here, so a read-model rebuild derives
-- the link for it.
CREATE TABLE IF NOT EXISTS pam_session_approval_links (
    tenant_id           uuid        NOT NULL,
    session_id          uuid        NOT NULL,
    approval_request_id uuid        NOT NULL,
    activated_at        timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, session_id)
);
ALTER TABLE pam_session_approval_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_session_approval_links FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pam_session_approval_links_isolation ON pam_session_approval_links;
CREATE POLICY pam_session_approval_links_isolation ON pam_session_approval_links
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pam_session_approval_links TO trstctl_app;

-- How a session's approval link is known: 'recorded' (its started event names
-- the approval, or was written by code that records the link, so none named
-- means none consumed), 'derived' (from the link above), or NULL: a row
-- projected before this column, which reads unrecorded unless it names an
-- approval. A rebuild gives every row its value.
ALTER TABLE pam_sessions ADD COLUMN IF NOT EXISTS approval_link text;
