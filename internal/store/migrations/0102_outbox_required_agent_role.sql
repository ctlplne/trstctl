-- Per-row agent-role demand on the outbox (epic A3, closing A2's stated gap).
--
-- A2 gated agent claims per job KIND: endpoint.verify is relay work,
-- discovery.run is host work. But connector.deploy is legitimately both — a
-- host agent deploys to the nginx beside it, a relay deploys to the F5 it can
-- reach — so the kind-level table had to leave it open to both roles, and said
-- so in docs/limitations.md. Which role a given deploy needs is a property of
-- the TARGET, and the enqueue path is the one place that knows the target and
-- consults the shipped vantage census (nativeConnectorVantage). So the demand
-- is stamped on the row at enqueue and read back at claim time, where the
-- claim SQL can filter on a plain column instead of decoding a sealed payload.
--
-- Vocabulary, chosen so one column carries the whole rule:
--   ''              — no per-row demand; kind-level vantage rules alone apply.
--                     Every row enqueued before this migration reads this way,
--                     which is exactly the behaviour those rows had.
--   'host'          — only an agent whose certificate carries the host role may
--                     claim this row.
--   'network'       — only a network relay may claim it.
--   'control_plane' — no agent may claim it, ever. This is the stamp for cloud
--                     certificate stores (ACM, Azure Key Vault, GCP CM): there
--                     is no host and no segment, so the work stays with the
--                     control plane's egress-guarded client. The value matches
--                     no agent role by construction, so the claim predicate
--                     needs no special case for it.
--
-- online-safe: ADD COLUMN with a constant default is catalog-only in
-- PostgreSQL 11+ — no table rewrite on the deployment's busiest table.
ALTER TABLE outbox
    ADD COLUMN IF NOT EXISTS required_agent_role text NOT NULL DEFAULT '';

-- The vocabulary is closed at the database so no repair script or hand edit can
-- stamp a demand the claim path has no meaning for.
ALTER TABLE outbox
    ADD CONSTRAINT outbox_required_agent_role_known
    CHECK (required_agent_role IN ('', 'host', 'network', 'control_plane'));

COMMENT ON COLUMN outbox.required_agent_role IS
    'Agent role this row demands at claim time (epic A3). Empty = kind-level rules only; control_plane = never agent-claimable.';
