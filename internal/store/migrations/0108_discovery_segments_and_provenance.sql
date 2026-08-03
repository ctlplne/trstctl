-- Coverage, provenance, and the blind spots nobody declared (epic C3).
--
-- The existing coverage surface classifies asset CLASSES against configured
-- source kinds. That answers "could this deployment ever see a Kubernetes
-- secret", and it is the right question at that level. It cannot answer the
-- question an operator actually asks during an audit: "which parts of my
-- network has anything looked at, when, and what is deliberately excluded".
--
-- A segment sweep already exists (C2), but a segment is only implied — it is a
-- CIDR list on a job payload, gone once the job completes. So there is no way
-- to say a segment exists and has NEVER been swept, which is precisely the
-- blind spot worth reporting. An inventory built only from what was found can
-- never report what was never looked at.
--
-- Hence a declared segment: an operator names the network they own, and the
-- coverage surface measures reality against that declaration rather than
-- against itself.

CREATE TABLE discovery_segments (
    tenant_id   uuid        NOT NULL,
    id          uuid        NOT NULL,
    name        text        NOT NULL,
    -- The declared boundary. Text rather than cidr[] because operators describe
    -- segments in forms Postgres's inet types reject — a hostname range, a
    -- vlan label, "everything behind the DMZ firewall" — and refusing those at
    -- the column would push the honest declaration out of the system entirely.
    ranges      text[]      NOT NULL DEFAULT '{}',
    -- staleness_hours is the operator's own SLO for this segment: past it, a
    -- sweep result is not evidence any more. It is per segment because a DMZ
    -- and a lab do not deserve the same answer.
    staleness_hours integer NOT NULL DEFAULT 168 CHECK (staleness_hours > 0),
    -- excluded segments are DECLARED blind spots: an operator has said, on the
    -- record, that this network is out of scope. That is a legitimate answer
    -- and completely different from a segment nobody has got to yet — which is
    -- why the reason is mandatory in practice and surfaced beside the flag.
    excluded         boolean NOT NULL DEFAULT false,
    exclusion_reason text    NOT NULL DEFAULT '',
    -- Observation state, written by a completed sweep.
    last_swept_at    timestamptz,
    last_swept_by    text    NOT NULL DEFAULT '',
    last_found_count integer NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name)
);

ALTER TABLE discovery_segments ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_segments FORCE ROW LEVEL SECURITY;

CREATE POLICY discovery_segments_isolation ON discovery_segments
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

-- The console's default question is "what is stale or never swept", so that is
-- what the index serves: nulls first, oldest first.
CREATE INDEX discovery_segments_freshness_idx
    ON discovery_segments (tenant_id, last_swept_at NULLS FIRST);

GRANT SELECT, INSERT, UPDATE, DELETE ON discovery_segments TO trstctl_app;

COMMENT ON TABLE discovery_segments IS
    'Operator-declared network segments and their sweep freshness (epic C3). Declaring a segment is what makes "never swept" reportable — an inventory built only from what was found cannot report what was never looked at.';

-- Per-asset provenance.
--
-- A certificate row says where it is deployed and what kind of source produced
-- it, but not WHICH source, nor when that source last actually saw it. Both
-- matter to anyone deciding whether an inventory row is current: a certificate
-- last observed by a cloud scan four months ago is a different fact from the
-- same row observed this morning, and the row looks identical without this.
--
-- last_seen_at is deliberately distinct from created_at. created_at is when
-- trstctl first recorded the certificate; last_seen_at is when something
-- confirmed it still exists. Conflating them makes a stale inventory look
-- freshly verified.
--
-- online-safe: three ADD COLUMNs with constant defaults, catalog-only in
-- PostgreSQL 11+.
ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS observed_by   text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS observed_kind text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_seen_at  timestamptz;

COMMENT ON COLUMN certificates.observed_by IS
    'The specific source or agent that last observed this certificate (epic C3). Empty means no observation is recorded — which is a real state for a certificate this control plane issued and nothing has since re-observed.';
COMMENT ON COLUMN certificates.last_seen_at IS
    'When something last confirmed this certificate still exists (epic C3). Distinct from created_at, which is when it was first recorded; conflating them makes a stale inventory look freshly verified.';
