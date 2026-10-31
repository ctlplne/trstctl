-- A163: a rogue certificate found in Certificate Transparency, revoked at the CA
-- that issued it through that CA's own revocation API. A projection of
-- rogue.certificate.revocation_requested and rogue.certificate.revoked_at_issuer;
-- one row per finding and authority. A failed attempt is the outbox row's own
-- state, never a value written here.
CREATE TABLE IF NOT EXISTS rogue_certificate_revocations (
    tenant_id        uuid        NOT NULL,
    discovery_id     uuid        NOT NULL,
    authority_id     text        NOT NULL CHECK (authority_id <> ''),
    request_event_id text        NOT NULL CHECK (request_event_id <> ''),
    serial           text        NOT NULL CHECK (serial ~ '^[0-9a-f]{1,64}$'),
    reason           text        NOT NULL CHECK (reason <> ''),
    state            text        NOT NULL CHECK (state IN ('queued', 'revoked')),
    requested_at     timestamptz NOT NULL,
    revoked_at       timestamptz,
    event_sequence   bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, discovery_id, authority_id)
);
ALTER TABLE rogue_certificate_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE rogue_certificate_revocations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS rogue_certificate_revocations_isolation ON rogue_certificate_revocations;
CREATE POLICY rogue_certificate_revocations_isolation ON rogue_certificate_revocations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON rogue_certificate_revocations TO trstctl_app;
