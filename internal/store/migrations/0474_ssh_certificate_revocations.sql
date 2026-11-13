-- SPDX-License-Identifier: BUSL-1.1

-- A245-L1: SSH certificate revocations as a read model, projected from
-- ssh.cert.revoked events (AN-2), so the operations ledger can list each
-- revocation and whether the hosts adopted it. A key ID can name a person,
-- so a row keeps only whether one was named, never the ID; the serial (a
-- decimal uint64), the operator's reason and the event's actor are kept as the
-- event keeps them.
CREATE TABLE IF NOT EXISTS ssh_certificate_revocations (
    tenant_id      uuid        NOT NULL,
    event_id       text        NOT NULL CHECK (event_id <> '' AND length(event_id) <= 64),
    serial         text        NOT NULL DEFAULT '' CHECK (serial ~ '^[0-9]{0,20}$'),
    by_key_id      boolean     NOT NULL DEFAULT false,
    reason         text        NOT NULL DEFAULT '',
    revoked_by     text        NOT NULL DEFAULT '',
    revoked_at     timestamptz NOT NULL,
    event_sequence bigint      NOT NULL CHECK (event_sequence >= 0),
    PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX IF NOT EXISTS ssh_certificate_revocations_recent
    ON ssh_certificate_revocations (tenant_id, revoked_at DESC, event_id DESC);
ALTER TABLE ssh_certificate_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssh_certificate_revocations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ssh_certificate_revocations_isolation ON ssh_certificate_revocations;
CREATE POLICY ssh_certificate_revocations_isolation ON ssh_certificate_revocations
    USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON ssh_certificate_revocations TO trstctl_app;
