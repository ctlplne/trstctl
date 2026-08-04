-- What each listener is ACTUALLY serving (epic D2).
--
-- Everything the platform knew about deployment until now was an account of
-- what it DID: an outbox row that delivered, a connector that returned success,
-- an inventory row for the certificate that was issued. All of those can be
-- true at once while the listener serves something else entirely, because a
-- connector's reload is one exec call inside its own Deploy method and nothing
-- downstream observes whether it took effect.
--
-- So this table records observations rather than intentions. Every row is the
-- result of a TLS handshake somebody actually performed, and the columns are
-- shaped so that a row can never claim more than the handshake established.

CREATE TABLE endpoint_verifications (
    tenant_id   uuid NOT NULL,
    -- endpoint_id is the listener this observation is about. It is stable
    -- across observations so history accumulates per endpoint rather than per
    -- probe, and it comes from the control plane's own job payload rather than
    -- from the agent's report: an agent naming a different endpoint in its
    -- result must not be able to overwrite another endpoint's state.
    endpoint_id text NOT NULL,
    -- address is host:port as dialled, kept for display. NOT the key: an
    -- operator correcting a typo in an address must not orphan the history.
    address     text NOT NULL,
    -- vantage says who looked: 'local' (the agent on the serving host, right
    -- after deploying) or 'relay' (a network agent, as a client would).
    --
    -- Part of the primary key, deliberately. The two answer different
    -- questions and one must never overwrite the other: a local pass means
    -- "the box thinks it is fine", a relay pass means "a client could get
    -- this", and an appliance has no local vantage at all.
    vantage     text NOT NULL CHECK (vantage IN ('local', 'relay')),

    -- reached says whether the handshake completed. Everything below is
    -- meaningful only when it is true, which the CHECK constraint enforces
    -- rather than trusting every writer to remember.
    reached     boolean NOT NULL DEFAULT false,
    -- mismatch is the divergence class, '' when the identity matched. The
    -- closed set is certinfo.Mismatches(); a class invented at a call site
    -- would reach an operator as a blank cell, so the database refuses it.
    mismatch    text NOT NULL DEFAULT ''
                CHECK (mismatch IN ('', 'fingerprint', 'sans', 'chain', 'expired', 'not_yet_valid')),
    -- An unreached probe cannot have classified anything. This is the same
    -- rule the transcript's Validate enforces on the agent, restated where it
    -- cannot be bypassed: an endpoint nobody could connect to must never be
    -- storable as verified.
    CONSTRAINT endpoint_verifications_unreached_claims_nothing
        CHECK (reached OR (mismatch = '' AND NOT checked_sans AND NOT checked_chain
                           AND observed_fingerprint = '')),

    expected_fingerprint text NOT NULL DEFAULT '',
    observed_fingerprint text NOT NULL DEFAULT '',
    -- checked_sans / checked_chain record which comparisons RAN. A verification
    -- that never received an expected SAN set must not be readable as having
    -- checked names — the console renders these, so "verified" always carries
    -- what it verified.
    checked_sans  boolean NOT NULL DEFAULT false,
    checked_chain boolean NOT NULL DEFAULT false,

    -- served validity window, for the console's expiry column. 0/NULL when
    -- nothing was served.
    not_before timestamptz,
    not_after  timestamptz,

    -- detail is the operator-facing explanation, already sanitized by the
    -- agent. Bounded by convention rather than by type: it is a hint, not a
    -- payload.
    detail text NOT NULL DEFAULT '',
    -- evidence_digest is the transcript digest inside the agent's signed
    -- receipt. It is what makes a verdict evidence rather than an assertion:
    -- an operator can prove the transcript they are reading is the one signed.
    evidence_digest text NOT NULL DEFAULT '',
    -- agent_common_name is who observed it, from the peer certificate on the
    -- report call, never from a request field (AN-1).
    agent_common_name text NOT NULL DEFAULT '',

    -- last_checked_at is when a probe last ran, whatever its outcome.
    -- last_good_at is when this endpoint was last observed serving what it
    -- should. The two together are the console's headline, and the GAP between
    -- them is the signal: an endpoint checked minutes ago and last good three
    -- weeks ago has been failing for three weeks.
    last_checked_at timestamptz NOT NULL,
    last_good_at    timestamptz,

    -- event_sequence makes the row replay-safe. Boot replays the whole log
    -- without truncating, so an observation applied twice must be idempotent;
    -- the timestamps are, but a naive upsert could still move state backwards
    -- when events arrive out of order.
    event_sequence bigint NOT NULL DEFAULT 0,

    PRIMARY KEY (tenant_id, endpoint_id, vantage)
);

COMMENT ON TABLE endpoint_verifications IS
    'Observed TLS identity per endpoint per vantage (epic D2): what a listener actually served, as against what the inventory says was deployed.';

-- AN-1. Every read and write is scoped by the session tenant, which comes from
-- the authenticated principal and never from a request field.
ALTER TABLE endpoint_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoint_verifications FORCE ROW LEVEL SECURITY;

CREATE POLICY endpoint_verifications_tenant_isolation ON endpoint_verifications
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- The console leads with what is diverging, then with what has gone longest
-- without a good observation.
CREATE INDEX endpoint_verifications_divergence
    ON endpoint_verifications (tenant_id, (mismatch <> '') DESC, last_good_at NULLS FIRST);

GRANT SELECT, INSERT, UPDATE, DELETE ON endpoint_verifications TO trstctl_app;
