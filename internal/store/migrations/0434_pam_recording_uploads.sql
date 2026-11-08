-- SPDX-License-Identifier: BUSL-1.1
-- A278: a gateway's recording chunk is accepted into this table, with its
-- outbox entry, in one transaction, so the upload returns without waiting on
-- the object store. The outbox worker writes the sealed object, records it
-- (pam.session.recording_chunk_stored) and deletes the row; staged bytes are
-- bounded, so a stalled object store pushes back on the uploading gateway
-- instead of holding its agent channel or dropping a chunk. Not a read model:
-- the outbox and this table are delivery state, recovered by redelivery.
CREATE TABLE pam_recording_uploads (
 tenant_id uuid NOT NULL,
 session_id uuid NOT NULL,
 attempt integer NOT NULL CHECK (attempt >= 1),
 seq integer NOT NULL CHECK (seq >= 0),
 ord integer NOT NULL CHECK (ord >= 0),
 gateway_agent_id uuid NOT NULL,
 sha256 text NOT NULL,
 sealed_sha256 text NOT NULL,
 chain text NOT NULL,
 size integer NOT NULL CHECK (size >= 0),
 final boolean NOT NULL,
 sealed bytea NOT NULL,
 staged_at timestamptz NOT NULL,
 PRIMARY KEY (tenant_id, session_id, attempt, seq),
 UNIQUE (tenant_id, session_id, ord)
);
ALTER TABLE pam_recording_uploads ENABLE ROW LEVEL SECURITY;
ALTER TABLE pam_recording_uploads FORCE ROW LEVEL SECURITY;
CREATE POLICY pam_recording_uploads_isolation ON pam_recording_uploads
 USING(tenant_id=current_setting('trstctl.tenant_id',true)::uuid)
 WITH CHECK(tenant_id=current_setting('trstctl.tenant_id',true)::uuid);
GRANT SELECT,INSERT,UPDATE,DELETE ON pam_recording_uploads TO trstctl_app;
