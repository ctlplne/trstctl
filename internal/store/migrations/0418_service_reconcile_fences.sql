-- Preserve the exact first approved directory reconciliation before publication.
-- Existing claim rows and tenant RLS remain unchanged; this adds one closed kind.
ALTER TABLE approved_target_event_fences
    DROP CONSTRAINT approved_target_event_fences_target_kind_check;
ALTER TABLE approved_target_event_fences
    ADD CONSTRAINT approved_target_event_fences_target_kind_check
    CHECK (target_kind IN ('ephemeral_certificate', 'code_signing_command', 'service_reconcile_rotation'));
