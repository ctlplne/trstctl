-- Secret-sync receiver settlement. A command whose first receiver start lost
-- its result is retried under the same operation ID; a later success or an
-- independent readback can then prove the receiver's exact state. Two new
-- effect states record that proof so the per-target FIFO barrier releases the
-- next command instead of holding every later version forever:
--   effect_settled     a delivered command whose receiver state was read back
--                      (or attested) as this command's value after >1 starts
--   failure_reconciled a failed command whose receiver state was read back
--                      (or attested) as never holding this command's value
ALTER TABLE outbox DROP CONSTRAINT IF EXISTS outbox_secret_sync_receiver_effect_state_chk;
ALTER TABLE outbox
    ADD CONSTRAINT outbox_secret_sync_receiver_effect_state_chk CHECK (
        secret_sync_receiver_effect_state IN ('none', 'effect_possible', 'failure_authorized', 'effect_settled', 'failure_reconciled')
        AND (
            (left(destination, 12) = 'secret.sync.' AND (
                (secret_sync_receiver_effect_state = 'none'
                    AND secret_sync_receiver_io_starts = 0
                    AND secret_sync_failure_detail = ''
                    AND secret_sync_failure_attempts = 0)
                OR (secret_sync_receiver_effect_state = 'effect_possible'
                    AND secret_sync_receiver_io_starts > 0
                    AND secret_sync_failure_detail = ''
                    AND secret_sync_failure_attempts = 0)
                OR (secret_sync_receiver_effect_state = 'effect_settled'
                    AND secret_sync_receiver_io_starts > 0
                    AND secret_sync_failure_detail = ''
                    AND secret_sync_failure_attempts = 0)
                OR (secret_sync_receiver_effect_state = 'failure_authorized'
                    AND secret_sync_receiver_io_starts >= 0
                    AND secret_sync_failure_detail <> ''
                    AND secret_sync_failure_attempts > 0)
                OR (secret_sync_receiver_effect_state = 'failure_reconciled'
                    AND secret_sync_receiver_io_starts >= 0
                    AND secret_sync_failure_detail <> ''
                    AND secret_sync_failure_attempts > 0)
            ))
            OR (left(destination, 12) <> 'secret.sync.'
                AND secret_sync_receiver_effect_state = 'none'
                AND secret_sync_receiver_io_starts = 0
                AND secret_sync_failure_detail = ''
                AND secret_sync_failure_attempts = 0)
        )
    );

-- The three guards learn the settled states. Transitions stay one-way and keep
-- the exact start count; terminal outbox status still needs matching domain
-- evidence; retention GC treats a settled or reconciled row like its original.
CREATE OR REPLACE FUNCTION secret_sync_guard_outbox_order()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
	trusted_postgres_state_restore boolean;
BEGIN
	trusted_postgres_state_restore :=
		current_user = (
			SELECT pg_get_userbyid(relation.relowner)
			  FROM pg_class AS relation
			 WHERE relation.oid = 'outbox'::regclass
		)
		AND coalesce(current_setting('trstctl.postgres_state_restore', true), '') = 'true';
	IF TG_OP = 'INSERT' THEN
		IF left(NEW.destination, 12) = 'secret.sync.'
		   AND NOT trusted_postgres_state_restore
		   AND (
               NEW.secret_sync_target_order IS NULL
               OR NEW.secret_sync_target_order <= 0
               OR NEW.secret_sync_order_from_event IS DISTINCT FROM true
               OR NEW.status <> 'pending'
               OR NEW.attempts <> 0
		       OR NEW.worker_id IS NOT NULL
		       OR NEW.lease_until IS NOT NULL
		       OR NEW.delivered_at IS NOT NULL
		       OR NEW.secret_sync_receiver_effect_state <> 'none'
		       OR NEW.secret_sync_receiver_io_starts <> 0
		       OR NEW.secret_sync_failure_detail <> ''
		       OR NEW.secret_sync_failure_attempts <> 0
		   ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'new secret-sync outbox rows require a positive AN-2 event order';
        END IF;
        RETURN NEW;
    END IF;

	IF (left(OLD.destination, 12) = 'secret.sync.'
	    OR left(NEW.destination, 12) = 'secret.sync.')
       AND (
           NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
           OR NEW.destination IS DISTINCT FROM OLD.destination
           OR NEW.secret_sync_target_order IS DISTINCT FROM OLD.secret_sync_target_order
           OR NEW.secret_sync_order_from_event IS DISTINCT FROM OLD.secret_sync_order_from_event
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '27000',
			MESSAGE = 'secret-sync outbox target order is immutable';
	END IF;

	-- The application role may enqueue the initial 'none'/zero state, but only the
	-- owner-role worker can move receiver authority forward. Neither the state nor
	-- start count ever moves backward: doing so would forget a prior or expired
	-- worker generation that may already have written to the receiver.
	IF (NEW.secret_sync_receiver_effect_state IS DISTINCT FROM OLD.secret_sync_receiver_effect_state
	    OR NEW.secret_sync_receiver_io_starts IS DISTINCT FROM OLD.secret_sync_receiver_io_starts
	    OR NEW.secret_sync_failure_detail IS DISTINCT FROM OLD.secret_sync_failure_detail
	    OR NEW.secret_sync_failure_attempts IS DISTINCT FROM OLD.secret_sync_failure_attempts)
	   AND (
	       left(OLD.destination, 12) <> 'secret.sync.'
	       OR current_user = 'trstctl_app'
	       OR NEW.secret_sync_receiver_io_starts < OLD.secret_sync_receiver_io_starts
	       OR OLD.secret_sync_receiver_effect_state IN ('failure_authorized', 'failure_reconciled', 'effect_settled')
	       OR (OLD.secret_sync_receiver_effect_state = 'effect_possible' AND NOT (
	           (NEW.secret_sync_receiver_effect_state = 'effect_possible'
	               AND NEW.secret_sync_receiver_io_starts > OLD.secret_sync_receiver_io_starts
	               AND NEW.secret_sync_failure_detail = ''
	               AND NEW.secret_sync_failure_attempts = 0)
	           OR (NEW.secret_sync_receiver_effect_state = 'failure_authorized'
	               AND OLD.secret_sync_receiver_io_starts = 1
	               AND NEW.secret_sync_receiver_io_starts = 1
	               AND NEW.secret_sync_failure_detail <> ''
	               AND NEW.secret_sync_failure_attempts > 0)
	           -- An independent receiver readback (or a recorded operator
	           -- attestation) settles a multi-start delivery or proves a
	           -- command never took effect; the start count is kept exactly.
	           OR (NEW.secret_sync_receiver_effect_state = 'effect_settled'
	               AND NEW.secret_sync_receiver_io_starts = OLD.secret_sync_receiver_io_starts
	               AND NEW.secret_sync_failure_detail = ''
	               AND NEW.secret_sync_failure_attempts = 0)
	           OR (NEW.secret_sync_receiver_effect_state = 'failure_reconciled'
	               AND NEW.secret_sync_receiver_io_starts = OLD.secret_sync_receiver_io_starts
	               AND NEW.secret_sync_failure_detail <> ''
	               AND NEW.secret_sync_failure_attempts > 0)
	       ))
	       OR (OLD.secret_sync_receiver_effect_state = 'none' AND NOT (
	           (NEW.secret_sync_receiver_effect_state = 'effect_possible'
	               AND NEW.secret_sync_receiver_io_starts > 0
	               AND NEW.secret_sync_failure_detail = ''
	               AND NEW.secret_sync_failure_attempts = 0)
	           OR (NEW.secret_sync_receiver_effect_state = 'failure_authorized'
	               AND NEW.secret_sync_receiver_io_starts = 0
	               AND NEW.secret_sync_failure_detail <> ''
	               AND NEW.secret_sync_failure_attempts > 0)
	       ))
	   ) THEN
		RAISE EXCEPTION USING
			ERRCODE = '55000',
			MESSAGE = 'secret-sync receiver-effect authority may only advance through the trusted worker or reconciler';
	END IF;
	RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION secret_sync_guard_outbox_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_target text;
    current_order bigint;
    current_status text;
BEGIN
    IF left(NEW.destination, 12) <> 'secret.sync.' THEN
        RETURN NEW;
    END IF;

    -- A terminal secret-sync fact is irreversible. Enqueue a fresh command with
    -- the current source value instead of reviving retained ciphertext.
    IF OLD.status IN ('failed', 'delivered')
       AND NEW.status IS DISTINCT FROM OLD.status THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'terminal secret-sync outbox status is immutable; enqueue a fresh sync command';
    END IF;

    -- The domain event is the effect truth and is projected before the generic
    -- outbox finalizer. Never let a mixed/buggy worker retire a still-pending job:
    -- doing so would remove its FIFO barrier and release a stale successor.
	IF NEW.status = 'delivered' AND OLD.status <> 'delivered'
	   AND NOT EXISTS (
           SELECT 1
             FROM secret_sync_jobs AS terminal_job
            WHERE terminal_job.tenant_id = NEW.tenant_id
	          AND terminal_job.outbox_id = NEW.id
	          AND terminal_job.target_order = NEW.secret_sync_target_order
	          AND (
	              (terminal_job.status = 'delivered'
	                  AND NEW.secret_sync_receiver_effect_state IN ('effect_possible', 'effect_settled'))
	              OR
	              (terminal_job.status = 'failed'
	                  AND (
	                      (NEW.secret_sync_receiver_effect_state IN ('failure_authorized', 'failure_reconciled')
	                          AND NEW.secret_sync_failure_detail = terminal_job.last_error
	                          AND NEW.secret_sync_failure_attempts = terminal_job.attempts)
	                      OR
	                      -- A negative-order failed row predates receiver receipts.
	                      -- Retiring its cleanup outbox is zero I/O and MUST NOT
	                      -- pretend the historical outcome was definitely no-effect;
	                      -- effect_possible remains its successor FIFO barrier.
	                      (terminal_job.target_order < 0
	                          AND NEW.secret_sync_order_from_event IS FALSE
	                          AND NEW.secret_sync_receiver_effect_state = 'effect_possible'
	                          AND NEW.secret_sync_receiver_io_starts > 0
	                          AND NEW.secret_sync_failure_detail = ''
	                          AND NEW.secret_sync_failure_attempts = 0)
	                  ))
	          )
	   ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'secret-sync outbox delivery requires terminal domain evidence';
    END IF;

    IF NEW.status = 'failed' AND OLD.status <> 'failed'
       AND NOT EXISTS (
           SELECT 1
             FROM secret_sync_jobs AS terminal_job
            WHERE terminal_job.tenant_id = NEW.tenant_id
	          AND terminal_job.outbox_id = NEW.id
	          AND terminal_job.target_order = NEW.secret_sync_target_order
	          AND terminal_job.status = 'failed'
	          AND NEW.secret_sync_receiver_effect_state IN ('failure_authorized', 'failure_reconciled')
	          AND NEW.secret_sync_failure_detail = terminal_job.last_error
	          AND NEW.secret_sync_failure_attempts = terminal_job.attempts
	   ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'secret-sync outbox failure requires failed domain evidence';
    END IF;

    IF NEW.status <> 'processing' OR OLD.status = 'processing' THEN
        RETURN NEW;
    END IF;

    SELECT job.target, job.target_order, job.status
      INTO current_target, current_order, current_status
      FROM secret_sync_jobs AS job
     WHERE job.tenant_id = NEW.tenant_id
       AND job.outbox_id = NEW.id
       AND job.target_order = NEW.secret_sync_target_order
       AND NEW.destination = 'secret.sync.' || job.target;

    -- RETURN NULL skips this complete row update, including its attempt increment.
    -- An old claim query therefore performs no receiver I/O; current SQL skips the
    -- row before UPDATE so a blocked target cannot starve another target.
    IF NOT FOUND OR current_status NOT IN ('pending', 'delivered', 'failed') THEN
        RETURN NULL;
    END IF;

	-- A terminal job makes this outbox row cleanup-only. Its handler returns before
	-- receiver lookup or payload open, so it can retire independently of ambiguous
	-- predecessors. The predecessor fence still controls every pending command.
	IF current_status IN ('delivered', 'failed') THEN
		RETURN NEW;
	END IF;

    -- An API may project a later event in a transaction that commits before an
    -- earlier event's live projection. Only the ordered tail/checkpoint proves all
    -- lower global sequences are visible. A stalled or poisoned tail therefore
    -- leaves the command safely unclaimable. Dense legacy backfill values are
    -- explicitly marked false and rely on the migration's one-runnable-row proof.
    IF NEW.secret_sync_order_from_event
       AND NOT EXISTS (
           SELECT 1
             FROM projection_checkpoint
            WHERE id = 1
              AND applied_seq >= current_order
       ) THEN
        RETURN NULL;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM outbox AS older_outbox
	      LEFT JOIN secret_sync_jobs AS older_job
	        ON older_job.tenant_id = older_outbox.tenant_id
	       AND older_job.outbox_id = older_outbox.id
	       AND older_job.target_order = older_outbox.secret_sync_target_order
	       AND older_outbox.destination = 'secret.sync.' || older_job.target
         WHERE older_outbox.tenant_id = NEW.tenant_id
           AND older_outbox.destination = NEW.destination
           AND older_outbox.secret_sync_target_order < current_order
	       AND NOT COALESCE(
	           (older_job.status = 'delivered'
	               AND ((older_outbox.secret_sync_receiver_effect_state = 'effect_possible'
	                       AND older_outbox.secret_sync_receiver_io_starts = 1)
	                    OR older_outbox.secret_sync_receiver_effect_state = 'effect_settled'))
	           OR
	           (older_job.status = 'failed'
	               AND ((older_outbox.secret_sync_receiver_effect_state = 'failure_authorized'
	                       AND older_outbox.secret_sync_receiver_io_starts BETWEEN 0 AND 1)
	                    OR older_outbox.secret_sync_receiver_effect_state = 'failure_reconciled')
	               AND older_outbox.secret_sync_failure_detail = older_job.last_error
	               AND older_outbox.secret_sync_failure_attempts = older_job.attempts),
	           false
	       )
    ) THEN
        RETURN NULL;
    END IF;

    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION secret_sync_guard_active_outbox_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF left(OLD.destination, 12) = 'secret.sync.'
       AND EXISTS (SELECT 1 FROM tenants WHERE tenant_id = OLD.tenant_id)
       AND NOT (
           -- This is the only ordinary retention-GC shape: a positive
           -- event-derived command, already finalized delivered, paired to an
           -- exact event-derived terminal job. Failed/pending/legacy rows remain
           -- durable FIFO evidence until tenant offboarding.
           OLD.status = 'delivered'
           AND OLD.secret_sync_order_from_event
           AND OLD.secret_sync_target_order > 0
	               AND EXISTS (
	                   SELECT 1
	                     FROM secret_sync_jobs AS terminal_job
                WHERE terminal_job.tenant_id = OLD.tenant_id
                  AND terminal_job.outbox_id = OLD.id
                  AND terminal_job.target_order = OLD.secret_sync_target_order
	                      AND (
	                          (terminal_job.status = 'delivered'
	                              AND ((OLD.secret_sync_receiver_effect_state = 'effect_possible'
	                                    AND OLD.secret_sync_receiver_io_starts = 1)
	                                   OR OLD.secret_sync_receiver_effect_state = 'effect_settled'))
	                          OR
	                          (terminal_job.status = 'failed'
	                              AND ((OLD.secret_sync_receiver_effect_state = 'failure_authorized'
	                                    AND OLD.secret_sync_receiver_io_starts BETWEEN 0 AND 1)
	                                   OR OLD.secret_sync_receiver_effect_state = 'failure_reconciled')
	                              AND OLD.secret_sync_failure_detail = terminal_job.last_error
	                              AND OLD.secret_sync_failure_attempts = terminal_job.attempts)
	                      )
	                      AND terminal_job.terminal_event_from_event
	               )
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'secret-sync outbox deletion requires eligible event-derived terminal GC or tenant offboarding';
    END IF;
    RETURN NULL;
END;
$$;
