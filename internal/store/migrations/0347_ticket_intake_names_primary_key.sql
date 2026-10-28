-- A225: no table references the old provider-only key.
-- online-safe: the replacement unique index was prepared by the online build in 0346, all key columns are already NOT NULL. This short metadata-only attachment is covered by the populated 0345-0347 content harness.
ALTER TABLE ticket_intake_schedules
    DROP CONSTRAINT ticket_intake_schedules_pkey,
    ADD CONSTRAINT ticket_intake_schedules_pkey
        PRIMARY KEY USING INDEX ticket_intake_schedules_named_key;
