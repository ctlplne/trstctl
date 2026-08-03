-- Per-certificate key custody (epic B5).
--
-- docs/custody.md answers "whose process made the key" per credential KIND,
-- which is the right level for a design review and the wrong level for an audit.
-- An auditor is not asking about ACME in general; they are asking about the
-- certificate in front of them, and the kind-level table cannot tell them
-- whether that one took the modern path or the deprecated server-keygen path
-- retained beside it.
--
-- So the answer is recorded per certificate, from what the issuing code
-- actually did. A certificate issued from an operator-supplied CSR records that
-- the control plane never held the key; one issued through server keygen
-- records that it did. Both are true of that certificate and neither requires
-- trusting the prose.
--
-- Empty means UNRECORDED, and that is a third answer rather than a default. A
-- certificate discovered by a network scan has an origin nobody observed, and
-- the console must render that as unknown rather than as reassurance — which is
-- why there is no 'unknown' member in the vocabulary that could be mistaken for
-- an observation.
--
-- online-safe: ADD COLUMN with a constant default is catalog-only in
-- PostgreSQL 11+, so this does not rewrite the inventory table.
ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS key_origin     text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS key_storage    text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS key_exportable text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS key_generated_by text NOT NULL DEFAULT '';

-- The vocabulary is closed at the database. A custody claim is evidence an
-- auditor reads, so no path — a repair script, a hand edit, a future importer —
-- may write a value the console has no meaning for.
ALTER TABLE certificates
    ADD CONSTRAINT certificates_key_origin_known
    CHECK (key_origin IN ('', 'requester', 'host_agent', 'device', 'control_plane', 'signer'));

ALTER TABLE certificates
    ADD CONSTRAINT certificates_key_storage_known
    CHECK (key_storage IN ('', 'locked_memory', 'file', 'os_store', 'pkcs11', 'device_bound'));

ALTER TABLE certificates
    ADD CONSTRAINT certificates_key_exportable_known
    CHECK (key_exportable IN ('', 'exportable', 'non_exportable'));

COMMENT ON COLUMN certificates.key_origin IS
    'Whose process generated this certificate''s private key (epic B5). Empty = unrecorded, which is a distinct answer from any observation.';
