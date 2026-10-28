-- A213: the SCT each CT log returned for a submission, whether it verified
-- against the log key the request named, and whether the log has proven the
-- entry is in its tree under a signed tree head. A projection of the
-- ct.sct.recorded and ct.inclusion.recorded events; one row per submission.
CREATE TABLE IF NOT EXISTS certificate_scts (
    tenant_id              uuid        NOT NULL,
    submission_id          uuid        NOT NULL,
    leaf_fingerprint       text        NOT NULL CHECK (leaf_fingerprint ~ '^[0-9a-f]{64}$'),
    log_url                text        NOT NULL CHECK (log_url <> ''),
    log_id                 text        NOT NULL DEFAULT '',
    entry_type             text        NOT NULL CHECK (entry_type IN ('certificate', 'precertificate')),
    sct_timestamp          timestamptz NOT NULL,
    sct_status             text        NOT NULL CHECK (sct_status IN ('verified', 'invalid', 'unverified')),
    sct_reason             text        NOT NULL DEFAULT '',
    leaf_hash              text        NOT NULL DEFAULT '',
    log_public_key         bytea,
    allow_private_endpoint boolean     NOT NULL DEFAULT false,
    private_egress_cidrs   text[]      NOT NULL DEFAULT '{}',
    inclusion_status       text        NOT NULL
                                       CHECK (inclusion_status IN ('pending', 'verified', 'not_included', 'proof_invalid', 'not_checked')),
    inclusion_reason       text        NOT NULL DEFAULT '',
    leaf_index             bigint,
    tree_size              bigint,
    root_hash              text        NOT NULL DEFAULT '',
    inclusion_checked_at   timestamptz,
    recorded_at            timestamptz NOT NULL,
    event_sequence         bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, submission_id)
);
CREATE INDEX IF NOT EXISTS certificate_scts_by_leaf ON certificate_scts (tenant_id, leaf_fingerprint);
CREATE INDEX IF NOT EXISTS certificate_scts_pending ON certificate_scts (tenant_id) WHERE inclusion_status = 'pending';
ALTER TABLE certificate_scts ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificate_scts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS certificate_scts_isolation ON certificate_scts;
CREATE POLICY certificate_scts_isolation ON certificate_scts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON certificate_scts TO trstctl_app;
