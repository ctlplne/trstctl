-- AUD-148: migration 0187 already scanned and validated the populated exact
-- diagnostic key with an online unique-index build. This transaction swaps
-- only PostgreSQL catalog ownership; it does not rebuild or rescan table data.

ALTER TABLE enrollment_diagnostics
    -- online-safe: attach the already-valid 0187 unique index as the primary key,
    -- the populated 0179->0187->0188 harness proves legacy and exact identities.
    DROP CONSTRAINT enrollment_diagnostics_pkey,
    ADD CONSTRAINT enrollment_diagnostics_pkey PRIMARY KEY
        USING INDEX enrollment_diagnostics_tenant_diagnostic_id_uq;

ALTER TABLE enrollment_diagnostics
    ADD CONSTRAINT enrollment_diagnostics_verification_kind_known
        CHECK (verification_kind IN ('', 'endpoint.verify')) NOT VALID,
    ADD CONSTRAINT enrollment_diagnostics_verification_sequence_nonnegative
        CHECK (verification_event_sequence >= 0) NOT VALID;

ALTER TABLE enrollment_diagnostics
    VALIDATE CONSTRAINT enrollment_diagnostics_verification_kind_known;
ALTER TABLE enrollment_diagnostics
    VALIDATE CONSTRAINT enrollment_diagnostics_verification_sequence_nonnegative;
