-- A138: multi-cluster TrustBundle rollouts.
--
-- A projection of the kubernetes.trust_rollout.* events and of each cluster's
-- authenticated posture reports. A rollout names one TrustBundle (public CA
-- certificates only) and an ordered list of clusters; the first is the canary.
-- A cluster is verified only when its own controller reports the bundle
-- distributed with the rollout's hash, and the rest are dispatched only once the
-- canary is verified. Both tables rebuild from the event log.
CREATE TABLE IF NOT EXISTS kubernetes_trust_rollouts (
    tenant_id       uuid        NOT NULL,
    id              uuid        NOT NULL,
    name            text        NOT NULL CHECK (name ~ '^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$'),
    ca_bundle_pem   text        NOT NULL CHECK (ca_bundle_pem <> ''),
    bundle_sha256   text        NOT NULL CHECK (bundle_sha256 ~ '^[0-9a-f]{64}$'),
    config_map_name text        NOT NULL CHECK (config_map_name <> ''),
    bundle_key      text        NOT NULL CHECK (bundle_key <> ''),
    namespaces      jsonb       NOT NULL CHECK (jsonb_typeof(namespaces) = 'array'),
    state           text        NOT NULL CHECK (state IN ('running', 'paused', 'completed', 'superseded')),
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    event_sequence  bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS kubernetes_trust_rollouts_by_name
    ON kubernetes_trust_rollouts (tenant_id, name, event_sequence DESC);
ALTER TABLE kubernetes_trust_rollouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE kubernetes_trust_rollouts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS kubernetes_trust_rollouts_isolation ON kubernetes_trust_rollouts;
CREATE POLICY kubernetes_trust_rollouts_isolation ON kubernetes_trust_rollouts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON kubernetes_trust_rollouts TO trstctl_app;

CREATE TABLE IF NOT EXISTS kubernetes_trust_rollout_clusters (
    tenant_id      uuid        NOT NULL,
    rollout_id     uuid        NOT NULL,
    cluster_id     text        NOT NULL CHECK (cluster_id ~ '^sha256:[0-9a-f]{64}$'),
    position       integer     NOT NULL CHECK (position >= 0),
    state          text        NOT NULL CHECK (state IN ('waiting', 'dispatched', 'verified', 'failed')),
    reason         text        NOT NULL DEFAULT '',
    report_id      text        NOT NULL DEFAULT '',
    observed_hash  text        NOT NULL DEFAULT '',
    dispatched_at  timestamptz,
    verified_at    timestamptz,
    event_sequence bigint      NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (tenant_id, rollout_id, cluster_id),
    UNIQUE (tenant_id, rollout_id, position),
    FOREIGN KEY (tenant_id, rollout_id) REFERENCES kubernetes_trust_rollouts (tenant_id, id) ON DELETE CASCADE,
    CHECK ((state = 'waiting') = (dispatched_at IS NULL)),
    CHECK ((state = 'verified') = (verified_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS kubernetes_trust_rollout_clusters_by_cluster
    ON kubernetes_trust_rollout_clusters (tenant_id, cluster_id);
ALTER TABLE kubernetes_trust_rollout_clusters ENABLE ROW LEVEL SECURITY;
ALTER TABLE kubernetes_trust_rollout_clusters FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS kubernetes_trust_rollout_clusters_isolation ON kubernetes_trust_rollout_clusters;
CREATE POLICY kubernetes_trust_rollout_clusters_isolation ON kubernetes_trust_rollout_clusters
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON kubernetes_trust_rollout_clusters TO trstctl_app;
