-- AUD-148: migration 0187 already scanned and validated the populated exact
-- diagnostic key with an online unique-index build. This transaction swaps
-- only PostgreSQL catalog ownership; it does not rebuild or rescan table data.

ALTER TABLE enrollment_diagnostics
    -- online-safe: attach the already-valid 0187 unique index as the primary key,
    -- the populated 0179->0187->0188 harness proves legacy and exact identities.
    DROP CONSTRAINT enrollment_diagnostics_pkey,
    ADD CONSTRAINT enrollment_diagnostics_pkey PRIMARY KEY
        USING INDEX enrollment_diagnostics_tenant_diagnostic_id_uq;

-- Migration 0179 originally shipped with these checks. Keep that immutable
-- history valid, while still letting a database built from the short-lived
-- deferred-check variant converge safely. Existing same-name checks came from
-- 0179 and are already validated; only absent checks need the online form.
DO $migration$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'enrollment_diagnostics'::regclass
           AND conname = 'enrollment_diagnostics_verification_kind_known'
    ) THEN
        ALTER TABLE enrollment_diagnostics
            ADD CONSTRAINT enrollment_diagnostics_verification_kind_known
                CHECK (verification_kind IN ('', 'endpoint.verify')) NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'enrollment_diagnostics'::regclass
           AND conname = 'enrollment_diagnostics_verification_sequence_nonnegative'
    ) THEN
        ALTER TABLE enrollment_diagnostics
            ADD CONSTRAINT enrollment_diagnostics_verification_sequence_nonnegative
                CHECK (verification_event_sequence >= 0) NOT VALID;
    END IF;
END
$migration$;

ALTER TABLE enrollment_diagnostics
    VALIDATE CONSTRAINT enrollment_diagnostics_verification_kind_known;
ALTER TABLE enrollment_diagnostics
    VALIDATE CONSTRAINT enrollment_diagnostics_verification_sequence_nonnegative;
