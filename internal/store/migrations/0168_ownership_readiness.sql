-- AUD-44 / epic I1: ownership is deployment authority, not display metadata.
--
-- The owner already carried the application model and last verification time.
-- These columns bind that verification to the authenticated human and the exact
-- model they saw, and remember which stale verification already produced a
-- re-attestation request so a minute scheduler cannot page once per minute.
ALTER TABLE owners
    ADD COLUMN IF NOT EXISTS ownership_verified_by text,
    ADD COLUMN IF NOT EXISTS ownership_model_digest text,
    ADD COLUMN IF NOT EXISTS ownership_reattestation_requested_at timestamptz,
    ADD COLUMN IF NOT EXISTS ownership_reattestation_requested_for timestamptz;

-- A deliberate, temporary exception is its own event-derived aggregate. It is
-- attached to one managed identity, names the authenticated grantor, explains
-- why normal ownership authority is unavailable, and expires by an immutable
-- wall-clock boundary. Expiry does not need a mutating timer to become effective:
-- every readiness decision compares expires_at with the event commit time.
CREATE TABLE ownership_readiness_exceptions (
    tenant_id       uuid        NOT NULL,
    id              uuid        NOT NULL,
    identity_id     uuid        NOT NULL,
    reason          text        NOT NULL,
    granted_by      text        NOT NULL,
    granted_at      timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    revoked_by      text,
    revoked_at      timestamptz,
    revocation_reason text,
    created_event_id text       NOT NULL,
    last_event_seq  bigint      NOT NULL,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, identity_id) REFERENCES identities (tenant_id, id),
    -- Command validation requires a reason. The read-model row deliberately
    -- permits an empty reason after a subject-erasure event clears free text;
    -- otherwise a cold replay of privacy-sanitized history would fail.
    CONSTRAINT ownership_readiness_exception_grantor_chk CHECK (btrim(granted_by) <> ''),
    CONSTRAINT ownership_readiness_exception_expiry_chk CHECK (expires_at > granted_at),
    CONSTRAINT ownership_readiness_exception_revocation_chk CHECK (
        (revoked_at IS NULL AND revoked_by IS NULL AND revocation_reason IS NULL)
        OR (revoked_at IS NOT NULL AND btrim(coalesce(revoked_by, '')) <> '' AND revocation_reason IS NOT NULL)
    )
);

ALTER TABLE ownership_readiness_exceptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ownership_readiness_exceptions FORCE ROW LEVEL SECURITY;

CREATE POLICY ownership_readiness_exceptions_isolation ON ownership_readiness_exceptions
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);

CREATE INDEX ownership_readiness_exceptions_identity_idx
    ON ownership_readiness_exceptions (tenant_id, identity_id, expires_at DESC, id);

GRANT SELECT, INSERT, UPDATE, DELETE ON ownership_readiness_exceptions TO trstctl_app;

COMMENT ON TABLE ownership_readiness_exceptions IS
    'Tenant-isolated event projection of attributed, reasoned, expiring ownership-readiness exceptions (AUD-44 / epic I1).';
