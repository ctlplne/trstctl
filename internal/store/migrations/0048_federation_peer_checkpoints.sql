-- Federation peer checkpoint (FED-01): one system cursor per source cluster that
-- records the highest source JetStream sequence imported into this cluster.
--
-- It carries no tenant_id by design: the source event-stream sequence is global
-- and monotonic per peer, so the import cursor is a deployment-wide system
-- watermark keyed by peer_id, like projection_checkpoint is keyed by the local
-- event log. Imported events themselves still carry tenant_id and are projected
-- through the normal RLS-bound read-model path.

CREATE TABLE IF NOT EXISTS federation_peer_checkpoints (
    peer_id    text PRIMARY KEY CHECK (peer_id <> ''),
    source_seq bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);
