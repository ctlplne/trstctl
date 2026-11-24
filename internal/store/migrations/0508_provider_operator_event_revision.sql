-- The latest projected authority event is the operator's durable revision.
-- A headerless SCIM command uses this to distinguish a fresh IdP decision
-- from a retry of the same request after the operator changes state.
ALTER TABLE provider_operators
    ADD COLUMN IF NOT EXISTS revision_event_id text NOT NULL DEFAULT '';
