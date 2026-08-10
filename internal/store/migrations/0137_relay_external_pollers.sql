-- AUD-45: scheduled external estate reads execute only as durable network-relay
-- jobs. Existing rows that already carry a secret-store reference can move to
-- that safer vantage without operator action. Rows that name an env: value are
-- disabled because that variable belongs to the control-plane process and
-- cannot honestly be redeemed by an estate relay.

-- AUD-94: older binaries closed an agent claim and delivered its outbox row in
-- two transactions. Any row left between those commits already represents an
-- agent-reported completed effect, so retire it once instead of handing that
-- external effect out forever to attempts that can no longer complete.
UPDATE outbox
   SET status = 'delivered',
       delivered_at = COALESCE(delivered_at, claim_completed_at),
       last_error = NULL,
       worker_id = NULL,
       lease_until = NULL
 WHERE status = 'pending'
   AND claim_completed_at IS NOT NULL;

UPDATE cmdb_reconcile_schedules
   SET execution = 'relay',
       enabled = enabled AND token_ref LIKE 'secret://%',
       last_error = CASE
           WHEN enabled AND token_ref NOT LIKE 'secret://%'
           THEN 'disabled during relay-only migration: configure a secret:// token_ref and re-enable'
           ELSE last_error
       END;

ALTER TABLE cmdb_reconcile_schedules
    ALTER COLUMN execution SET DEFAULT 'relay',
    ALTER COLUMN execution SET NOT NULL;

ALTER TABLE cmdb_reconcile_schedules
    ADD CONSTRAINT cmdb_reconcile_execution_relay_only CHECK (execution = 'relay');

UPDATE mdm_poll_schedules
   SET execution = 'relay',
       enabled = enabled AND token_ref LIKE 'secret://%',
       last_error = CASE
           WHEN enabled AND token_ref NOT LIKE 'secret://%'
           THEN 'disabled during relay-only migration: configure a secret:// token_ref and re-enable'
           ELSE last_error
       END;

ALTER TABLE mdm_poll_schedules
    ALTER COLUMN execution SET DEFAULT 'relay',
    ALTER COLUMN execution SET NOT NULL;

ALTER TABLE mdm_poll_schedules
    ADD CONSTRAINT mdm_poll_execution_relay_only CHECK (execution = 'relay');

UPDATE ticket_intake_schedules
   SET enabled = enabled AND token_ref LIKE 'secret://%',
       last_error = CASE
           WHEN enabled AND token_ref NOT LIKE 'secret://%'
           THEN 'disabled during relay-only migration: configure a secret:// token_ref and re-enable'
           ELSE last_error
       END;

-- A stable source event makes conflict projection idempotent. Nullable keeps
-- historical rows honest: migrations do not fabricate the event that created
-- an old conflict.
ALTER TABLE owner_ownership_conflicts
    ADD COLUMN source_event_id text;

COMMENT ON COLUMN owner_ownership_conflicts.source_event_id IS
    'Event identity that projected this conflict; NULL only for rows created before AUD-45. Makes relay-result and event replay idempotent.';
