-- One independently committed authority receiver per tenant/source. A pending
-- replacement blocks old trust before its source event reaches the projection.
CREATE TABLE workload_attester_trust_commands (
    tenant_id uuid NOT NULL,
    source_id uuid NOT NULL,
    event_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type IN (
        'workload.attester_trust_source.upserted',
        'workload.attester_trust_source.rotated',
        'workload.attester_trust_source.revoked',
        'workload.attester_trust_source.deleted')),
    event_time timestamptz NOT NULL,
    event_actor jsonb,
    event_payload bytea,
    payload_sha256 char(64),
    binding_sha256 char(64) NOT NULL CHECK (binding_sha256 ~ '^[0-9a-f]{64}$'),
    request_binding char(64) NOT NULL CHECK (request_binding ~ '^[0-9a-f]{64}$'),
    target_disabled boolean NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    projected_sequence bigint,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source_id),
    UNIQUE (tenant_id, event_id),
    CHECK ((status = 'pending' AND event_payload IS NOT NULL AND
            payload_sha256 ~ '^[0-9a-f]{64}$' AND projected_sequence IS NULL) OR
           (status = 'completed' AND event_payload IS NULL AND event_actor IS NULL AND
            payload_sha256 IS NULL AND projected_sequence > 0))
);
CREATE INDEX workload_attester_trust_commands_pending
    ON workload_attester_trust_commands (tenant_id, source_id)
    WHERE status = 'pending';
ALTER TABLE workload_attester_trust_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE workload_attester_trust_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY workload_attester_trust_commands_isolation ON workload_attester_trust_commands
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON workload_attester_trust_commands TO trstctl_app;

-- Keep the exact completed response when a later command replaces the current
-- source fence. A retry after a lost HTTP response must never republish an old
-- event or infer its answer from the source's newer posture.
CREATE TABLE workload_attester_trust_receipts (
    tenant_id uuid NOT NULL,
    event_id uuid NOT NULL,
    source_id uuid NOT NULL,
    event_type text NOT NULL,
    request_binding char(64) NOT NULL CHECK (request_binding ~ '^[0-9a-f]{64}$'),
    binding_sha256 char(64) NOT NULL CHECK (binding_sha256 ~ '^[0-9a-f]{64}$'),
    response_snapshot jsonb,
    projected_sequence bigint NOT NULL CHECK (projected_sequence > 0),
    completed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX workload_attester_trust_receipts_source
    ON workload_attester_trust_receipts (tenant_id, source_id, projected_sequence DESC);
ALTER TABLE workload_attester_trust_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE workload_attester_trust_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY workload_attester_trust_receipts_isolation ON workload_attester_trust_receipts
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON workload_attester_trust_receipts TO trstctl_app;
