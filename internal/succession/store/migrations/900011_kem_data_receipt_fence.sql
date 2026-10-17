-- A paired-key record proves signer custody, not that tenant ciphertext was
-- rewrapped. Prior builds projected it as completed data work. Keep the public
-- paired record, but retract that unsupported serving assertion on upgrade.
ALTER TABLE pcas_rewrap_job ADD COLUMN data_receipt_sequence bigint NOT NULL DEFAULT 0;
UPDATE pcas_rewrap_job
   SET status = 'key_ready', completed_stages = 0
 WHERE status = 'complete' AND data_receipt_sequence = 0;
