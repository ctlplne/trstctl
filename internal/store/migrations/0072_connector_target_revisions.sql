-- WIRE-CONN-000: a connector outbox retry must use the exact tenant target
-- configuration selected when the intent was emitted, not whatever happens to
-- be current after an operator edit. Event IDs are immutable revision IDs.

ALTER TABLE deployment_targets
    ADD COLUMN revision_id text,
    ADD COLUMN enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();

UPDATE deployment_targets
   SET revision_id = 'legacy:' || id::text
 WHERE revision_id IS NULL;

ALTER TABLE deployment_targets ALTER COLUMN revision_id SET NOT NULL;

CREATE TABLE deployment_target_revisions (
    tenant_id   uuid        NOT NULL,
    target_id   uuid        NOT NULL,
    revision_id text        NOT NULL,
    name        text        NOT NULL,
    type        text        NOT NULL,
    config      jsonb       NOT NULL DEFAULT '{}',
    enabled     boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, target_id, revision_id)
);

INSERT INTO deployment_target_revisions
       (tenant_id, target_id, revision_id, name, type, config, enabled, created_at)
SELECT tenant_id, id, revision_id, name, type, config, enabled, created_at
  FROM deployment_targets
ON CONFLICT DO NOTHING;

CREATE INDEX deployment_target_revisions_lookup_idx
    ON deployment_target_revisions (tenant_id, target_id, created_at DESC, revision_id);

ALTER TABLE deployment_target_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE deployment_target_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY deployment_target_revisions_isolation ON deployment_target_revisions
    USING (tenant_id = current_setting('trstctl.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON deployment_target_revisions TO trstctl_app;
