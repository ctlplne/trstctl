-- Upstream authorization staleness: seeing it before it expires (epic B7).
--
-- Solving DNS-01 upstream is only half of what the compressing validation-reuse
-- window demands. The other half is knowing whether you can still solve it.
--
-- An authority that already considers an identifier authorized issues without a
-- challenge. That is normal, it is fast, and it is exactly what hides a broken
-- validation path: an install whose authorizations are all reused has not
-- demonstrated it can validate for months, and it finds out on the day the
-- window closes — for every domain at once, because they were all authorized in
-- the same original burst and therefore all expire together.
--
-- So the reuse is recorded rather than merely enjoyed, and the surface reports
-- the LAST TIME EACH IDENTIFIER ACTUALLY VALIDATED, not the last time it
-- issued. Those two numbers diverge silently, and the gap between them is the
-- warning.

CREATE TABLE acme_upstream_authorizations (
    tenant_id       uuid        NOT NULL,
    -- identifier keeps its leading "*." for wildcards. A wildcard and its base
    -- name are different authorizations with different CAA requirements, and
    -- collapsing them here would report one as covering the other.
    identifier      text        NOT NULL,
    -- issuer is the authority that authorized it. The same name can be
    -- authorized at two CAs with independent reuse windows, and an operator
    -- migrating between them needs to see both rows, not their union.
    issuer          text        NOT NULL,
    -- challenge_type is empty when the authorization was REUSED: the authority
    -- returned it already valid and no challenge was solved. That emptiness is
    -- the signal, so it is a real distinction rather than a null.
    challenge_type  text        NOT NULL DEFAULT '',
    -- last_validated_at is when a challenge was actually solved for this
    -- identifier. NULL means trstctl has never once validated it here — every
    -- issuance so far rode a reuse this install did not earn and cannot repeat.
    last_validated_at timestamptz,
    -- last_reused_at is when the authority last waived the challenge.
    last_reused_at  timestamptz,
    -- expires_at is the authority's own stated expiry for the authorization,
    -- when it gives one. It is the authority's number, not a local guess: a
    -- computed estimate would keep looking right as the CA/Browser Forum moves
    -- the window underneath it.
    expires_at      timestamptz,
    reuse_count     bigint      NOT NULL DEFAULT 0,
    validate_count  bigint      NOT NULL DEFAULT 0,
    -- event_sequence is what makes the counters survive a replay.
    --
    -- Boot replays the WHOLE log without truncating (only Projector.Rebuild
    -- truncates), and the durable tailer can re-deliver an event the inline
    -- path already applied. The package contract is explicit that applying an
    -- already-projected event must be an idempotent upsert — and a counter that
    -- reads "count + 1" is the one shape of upsert that is not. Without this
    -- column every restart would inflate the reuse and validation totals by the
    -- entire history, and the console would report a validation record the
    -- deployment never earned.
    event_sequence  bigint      NOT NULL DEFAULT 0,
    observed_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, issuer, identifier)
);

-- AN-1. Every read and write is scoped by the session tenant, which comes from
-- the authenticated principal and never from a request field.
ALTER TABLE acme_upstream_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE acme_upstream_authorizations FORCE ROW LEVEL SECURITY;

CREATE POLICY acme_upstream_authorizations_tenant_isolation ON acme_upstream_authorizations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- The staleness query sorts never-validated rows above everything, then by what
-- expires soonest. The index leads with the same two keys.
--
-- The first key is not the obvious one: an identifier this install has never
-- validated may carry a comfortable expiry, because the authority keeps
-- reissuing from an authorization the install did not earn. Ordering by expiry
-- alone would bury exactly the rows an operator has to act on.
CREATE INDEX acme_upstream_authorizations_staleness
    ON acme_upstream_authorizations ((last_validated_at IS NULL) DESC, tenant_id, expires_at NULLS FIRST);

GRANT SELECT, INSERT, UPDATE, DELETE ON acme_upstream_authorizations TO trstctl_app;
