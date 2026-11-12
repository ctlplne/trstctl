-- X3-L1: an endpoint whose served certificate changed — a plain renewal's
-- deployment, or any other replacement — waits for wire evidence the way a
-- migration run's member does: an observer agent seeing new connections at
-- the endpoint after the replacement went live. The endpoint keeps which
-- certificate was replaced and when, then the evidence (when, which observer
-- finding) or, once its window has passed without any, since when it has been
-- unobserved. All nullable: an endpoint that has not been replaced since has
-- none of them.
ALTER TABLE endpoint_verifications
    ADD COLUMN IF NOT EXISTS replaced_fingerprint text,
    ADD COLUMN IF NOT EXISTS replaced_at timestamptz,
    ADD COLUMN IF NOT EXISTS traffic_observed_at timestamptz,
    ADD COLUMN IF NOT EXISTS traffic_finding_id text,
    ADD COLUMN IF NOT EXISTS traffic_unobserved_since timestamptz;
