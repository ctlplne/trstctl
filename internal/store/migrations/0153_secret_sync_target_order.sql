-- 0153_secret_sync_target_order.sql -- event-ordered causal FIFO for secret sync.
--
-- A target may normalize different raw key spellings to the same external object.
-- The safe ordering unit is therefore the whole tenant+target. New commands use
-- their immutable AN-2 event sequence as target_order; PostgreSQL stores the same
-- value on the projected job and retained outbox command, then blocks any claim
-- that could overtake an older nonterminal command.

-- Claiming commits before receiver I/O. The release runbook first quiesces old
-- producers while old workers drain/reconcile, then stops the final old process
-- before this migration. These locks prevent a stray writer from changing either
-- half while the legacy-state preflight runs. A pending outbox row paired to an
-- already-terminal job is cleanup-only: the domain event won, and the new handler
-- acknowledges that row without opening its sealed value or calling a receiver.
LOCK TABLE outbox, secret_sync_jobs IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM outbox AS queued
         WHERE left(queued.destination, 12) = 'secret.sync.'
           AND (
               queued.status = 'processing'
               OR (
                   queued.status = 'pending'
                   AND NOT EXISTS (
                       SELECT 1
                         FROM secret_sync_jobs AS terminal_job
                        WHERE terminal_job.tenant_id = queued.tenant_id
                          AND terminal_job.outbox_id = queued.id
                          AND queued.destination = 'secret.sync.' || terminal_job.target
                          AND terminal_job.status IN ('delivered', 'failed')
                   )
               )
           )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'secret-sync target-order migration requires zero runnable pending or processing secret.sync outbox rows';
    END IF;
END;
$$;

-- A pre-0153 pending job has no trustworthy causal rank. The outbox preflight
-- above rejects every runnable receiver; this second check also rejects a
-- malformed pending job paired to a terminal outbox.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM secret_sync_jobs
         WHERE status = 'pending'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'secret-sync target-order migration requires zero pending secret-sync commands';
    END IF;
END;
$$;

-- Freeze only terminal facts a canonical v2 projector can reproduce. Blessing a
-- zero-attempt delivery or an empty failure would make warm SQL impossible to
-- derive from retained history on the next rebuild.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM secret_sync_jobs
         WHERE (status = 'delivered' AND (
                   attempts <= 0 OR last_error <> '' OR delivered_at IS NULL
               ))
            OR (status = 'failed' AND (
                   attempts <= 0 OR last_error = '' OR remote_version <> '' OR delivered_at IS NOT NULL
               ))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'secret-sync target-order migration found noncanonical terminal job evidence';
    END IF;
END;
$$;

-- Every retained secret-sync outbox fact must have one exact projected job. A
-- compatibility-only row has no authenticated command semantics or tenant epoch;
-- terminal SQL status alone cannot prove whether a receiver generation is still
-- capable of writing. Reconcile it before the migration rather than blessing an
-- orphan as a FIFO release point.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM outbox AS queued
         WHERE left(queued.destination, 12) = 'secret.sync.'
           AND NOT EXISTS (
               SELECT 1
                 FROM secret_sync_jobs AS job
                WHERE job.tenant_id = queued.tenant_id
                  AND job.outbox_id = queued.id
           )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'secret-sync target-order migration found an outbox row without a projected job; reconcile it with the old release before retrying';
    END IF;
END;
$$;

-- The receiver idempotency key is the durable external-command identity. A
-- duplicate makes rebuild attachment ambiguous even when the two rows happen to
-- carry the same bytes, so stop before choosing one by SQL allocation order.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM outbox
         WHERE left(destination, 12) = 'secret.sync.'
         GROUP BY tenant_id, idempotency_key
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'secret-sync target-order migration found a duplicate secret-sync outbox receiver key';
    END IF;
END;
$$;

-- A row pair is one authenticated command, not merely two rows joined by an id.
-- Validate the exact receiver key and the immutable payload binding before
-- assigning any causal order. Malformed JSON/UTF-8/base64 also fails closed: an
-- operator must reconcile it with event history, never let a new worker guess.
DO $$
DECLARE
    command_row record;
    payload_json jsonb;
    sealed_payload bytea;
BEGIN
    FOR command_row IN
        SELECT job.id AS job_id,
               job.target,
               job.remote_key,
               job.idempotency_key AS job_idempotency_key,
               job.request_binding,
               queued.idempotency_key AS outbox_idempotency_key,
               queued.effect_lane,
               queued.payload
          FROM secret_sync_jobs AS job
          JOIN outbox AS queued
            ON queued.tenant_id = job.tenant_id
           AND queued.id = job.outbox_id
    LOOP
        BEGIN
            payload_json := convert_from(command_row.payload, 'UTF8')::jsonb;
            sealed_payload := decode(payload_json->>'sealed', 'base64');
        EXCEPTION WHEN OTHERS THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'secret-sync target-order migration found a malformed or job-mismatched outbox command';
        END;

        IF command_row.outbox_idempotency_key IS DISTINCT FROM command_row.job_idempotency_key
           OR (command_row.effect_lane <> ''
               AND command_row.effect_lane <> 'secret.sync:' || command_row.target)
           OR jsonb_typeof(payload_json) IS DISTINCT FROM 'object'
           OR payload_json->>'id' IS DISTINCT FROM command_row.job_id
           OR payload_json->>'target' IS DISTINCT FROM command_row.target
           OR payload_json->>'key' IS DISTINCT FROM command_row.remote_key
           OR coalesce(payload_json->>'request_binding', '') IS DISTINCT FROM command_row.request_binding
           OR sealed_payload IS NULL
           OR octet_length(sealed_payload) = 0 THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'secret-sync target-order migration found a malformed or job-mismatched outbox command';
        END IF;
    END LOOP;
END;
$$;

-- A worker projects terminal evidence before finalizing its outbox row. The first
-- preflight excludes every processing row and every runnable pending row while
-- preserving the recognized terminal-job/pending-outbox cleanup window. Every
-- remaining pair must therefore be one recognized terminal outcome.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM secret_sync_jobs AS job
          LEFT JOIN outbox AS queued
            ON queued.tenant_id = job.tenant_id
           AND queued.id = job.outbox_id
         WHERE queued.id IS NULL
            OR (queued.id IS NOT NULL AND (
                queued.destination <> 'secret.sync.' || job.target
                OR (job.status = 'pending' AND queued.status <> 'pending')
                OR (job.status = 'delivered' AND queued.status NOT IN ('pending', 'delivered'))
                -- outbox.delivered means the handler completed. Offline-disabled
                -- targets intentionally project domain failure and return nil, so
                -- failed+delivered is terminal and performs no future receiver I/O.
                OR (job.status = 'failed' AND queued.status NOT IN ('pending', 'failed', 'delivered'))
            ))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'secret-sync target-order migration found a job/outbox state mismatch; reconcile the interrupted command before retrying';
    END IF;
END;
$$;

-- Outbox ids were allocated before commit and are not AN-2 causal authority. A
-- legacy runnable command cannot be ordered honestly relative to ANY same-target
-- peer: a lower id may have committed/delivered after it, or a higher id before it.
-- This is defense in depth after the zero-runnable-row preflight: a malformed
-- runnable pair must never reach the rank backfill. All-terminal history can be
-- ranked arbitrarily because its pending outbox residue is cleanup-only and can
-- perform no receiver I/O.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM secret_sync_jobs AS runnable_job
          JOIN outbox AS runnable_outbox
            ON runnable_outbox.tenant_id = runnable_job.tenant_id
           AND runnable_outbox.id = runnable_job.outbox_id
         WHERE runnable_job.status = 'pending'
           AND runnable_outbox.status IN ('pending', 'processing')
           AND (
               EXISTS (
                   SELECT 1
                     FROM secret_sync_jobs AS peer_job
                    WHERE peer_job.tenant_id = runnable_job.tenant_id
                      AND peer_job.target = runnable_job.target
                      AND peer_job.id <> runnable_job.id
               )
               OR EXISTS (
                   SELECT 1
                     FROM outbox AS peer_outbox
                    WHERE peer_outbox.tenant_id = runnable_outbox.tenant_id
                      AND peer_outbox.destination = runnable_outbox.destination
                      AND peer_outbox.id <> runnable_outbox.id
               )
           )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'secret-sync target-order migration found a runnable command sharing a target with legacy history; drain or reconcile that target before retrying';
    END IF;
END;
$$;

-- Even one runnable row is unsafe if a later-allocated same-target row has already
-- been attempted or finalized: history has overtaken it and a rank backfill cannot
-- undo that receiver state.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM secret_sync_jobs AS older_job
          JOIN outbox AS older_outbox
            ON older_outbox.tenant_id = older_job.tenant_id
           AND older_outbox.id = older_job.outbox_id
          JOIN secret_sync_jobs AS newer_job
            ON newer_job.tenant_id = older_job.tenant_id
           AND newer_job.target = older_job.target
           AND newer_job.outbox_id > older_job.outbox_id
          JOIN outbox AS newer_outbox
            ON newer_outbox.tenant_id = newer_job.tenant_id
           AND newer_outbox.id = newer_job.outbox_id
         WHERE older_job.status = 'pending'
           AND older_outbox.status IN ('pending', 'processing')
           AND (
               newer_outbox.attempts > 0
               OR newer_outbox.status IN ('processing', 'delivered', 'failed')
               OR newer_job.status IN ('delivered', 'failed')
           )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'secret-sync target-order migration found an inherited same-target delivery inversion; reconcile the target before retrying';
    END IF;
END;
$$;

ALTER TABLE outbox
    ADD COLUMN secret_sync_target_order bigint,
    ADD COLUMN secret_sync_order_from_event boolean,
    -- These are command-global receiver authority, not retry bookkeeping. Once a
    -- generation crosses the receiver boundary, effect_possible stays sticky.
    -- The monotonic start count lets a typed no-I/O result prove it was the only
    -- generation that ever crossed; ordinary retries can never erase ambiguity.
    -- Failure detail and attempt count are frozen before the event append, so a
    -- later expired-lease claim reconstructs byte-identical canonical evidence.
    ADD COLUMN secret_sync_receiver_effect_state text NOT NULL DEFAULT 'none',
    ADD COLUMN secret_sync_receiver_io_starts bigint NOT NULL DEFAULT 0,
    ADD COLUMN secret_sync_failure_detail text NOT NULL DEFAULT '',
    ADD COLUMN secret_sync_failure_attempts integer NOT NULL DEFAULT 0;

ALTER TABLE secret_sync_jobs
    ADD COLUMN target_order bigint,
    ADD COLUMN tenant_epoch text NOT NULL DEFAULT '',
    ADD COLUMN terminal_event_id text NOT NULL DEFAULT '',
    ADD COLUMN terminal_event_type text NOT NULL DEFAULT '',
    ADD COLUMN terminal_event_sequence bigint,
    ADD COLUMN terminal_event_digest text NOT NULL DEFAULT '',
    ADD COLUMN terminal_event_from_event boolean;

-- Legacy projected jobs have no stored event sequence. Rank only the paired jobs,
-- not unrelated outbox traffic. There can be at most one runnable row per target,
-- and the inversion preflight proved it has not been overtaken. All future event
-- AN-2 sequences are positive, so their order domain cannot collide with
-- this dense negative legacy prefix.
WITH ranked AS (
    SELECT tenant_id, id,
           -row_number() OVER (
               PARTITION BY tenant_id, target
               ORDER BY outbox_id, id
           ) AS target_order
      FROM secret_sync_jobs
)
UPDATE secret_sync_jobs AS job
   SET target_order = ranked.target_order
  FROM ranked
 WHERE job.tenant_id = ranked.tenant_id
   AND job.id = ranked.id;

-- Standalone sync commands share the application-secret registration lifecycle:
-- their plaintext source is an application secret, and offboarding must rotate
-- both namespaces together. Seed an epoch for a legacy tenant that never used the
-- newer mutation surface, then bind every inherited row to it.
INSERT INTO application_secret_tenant_epochs (tenant_id, epoch_id)
SELECT DISTINCT tenant_id, gen_random_uuid()
  FROM secret_sync_jobs
ON CONFLICT (tenant_id) DO NOTHING;

UPDATE secret_sync_jobs AS job
   SET tenant_epoch = epoch.epoch_id::text
  FROM application_secret_tenant_epochs AS epoch
 WHERE epoch.tenant_id = job.tenant_id;

UPDATE outbox AS queued
	   SET secret_sync_target_order = job.target_order,
	       secret_sync_order_from_event = false,
	       secret_sync_receiver_effect_state = CASE job.status
	           WHEN 'failed' THEN 'effect_possible'
	           WHEN 'delivered' THEN 'effect_possible'
	           ELSE 'none'
	       END,
	       secret_sync_receiver_io_starts = CASE job.status
	           WHEN 'delivered' THEN GREATEST(job.attempts, queued.attempts, 1)
	           WHEN 'failed' THEN GREATEST(job.attempts, queued.attempts, 1)
	           ELSE 0
	       END,
	       secret_sync_failure_detail = '',
	       secret_sync_failure_attempts = 0
  FROM secret_sync_jobs AS job
 WHERE queued.tenant_id = job.tenant_id
   AND queued.id = job.outbox_id;

-- Pre-0153 terminal rows predate the receipt columns. Preserve their first
-- terminal database fact as an explicitly synthetic migration receipt; new
-- terminal transitions below must carry a real deterministic AN-2 identity.
UPDATE secret_sync_jobs
   SET terminal_event_id = 'legacy-0153-secret-sync:' || tenant_id::text || ':' || id,
       terminal_event_type = 'legacy.secret.sync.' || status,
       terminal_event_sequence = abs(target_order),
       terminal_event_digest = encode(sha256(convert_to(
           status || chr(31) || attempts::text || chr(31) || remote_version || chr(31) ||
           last_error || chr(31) || coalesce(delivered_at::text, '') || chr(31) || updated_at::text,
           'UTF8'
       )), 'hex'),
       terminal_event_from_event = false
 WHERE status IN ('failed', 'delivered');

-- online-safe: 0153 is an explicit fleet-stop migration; the runbook drains all
-- secret-sync claims and this transaction locks both command tables before the
-- bounded backfill/validation so no writer can observe a half-installed order.
ALTER TABLE secret_sync_jobs
    ALTER COLUMN target_order SET NOT NULL,
    ALTER COLUMN tenant_epoch DROP DEFAULT,
    ADD CONSTRAINT secret_sync_jobs_tenant_epoch_nonempty_chk
        CHECK (tenant_epoch <> ''),
    ADD CONSTRAINT secret_sync_jobs_target_order_nonzero_chk
        CHECK (target_order <> 0),
    ADD CONSTRAINT secret_sync_jobs_terminal_event_shape_chk CHECK (
        (status = 'pending'
            AND terminal_event_id = ''
            AND terminal_event_type = ''
            AND terminal_event_sequence IS NULL
            AND terminal_event_digest = ''
            AND terminal_event_from_event IS NULL)
        OR
        (status IN ('failed', 'delivered')
            AND terminal_event_id <> ''
            AND terminal_event_sequence > 0
            AND terminal_event_digest ~ '^[0-9a-f]{64}$'
            AND terminal_event_from_event IS NOT NULL
            AND (
                (terminal_event_from_event
                    AND terminal_event_type = 'secret.sync.' || status)
                OR
                (NOT terminal_event_from_event
                    AND terminal_event_type = 'legacy.secret.sync.' || status)
            ))
    );

ALTER TABLE outbox
    ADD CONSTRAINT outbox_secret_sync_target_order_chk
        CHECK (
            (left(destination, 12) = 'secret.sync.'
                AND secret_sync_target_order <> 0
                AND secret_sync_order_from_event IS NOT NULL)
            OR
            (left(destination, 12) <> 'secret.sync.'
                AND secret_sync_target_order IS NULL
                AND secret_sync_order_from_event IS NULL)
        );

ALTER TABLE outbox
    ADD CONSTRAINT outbox_secret_sync_target_order_source_chk CHECK (
        left(destination, 12) <> 'secret.sync.'
        OR (secret_sync_order_from_event AND secret_sync_target_order > 0)
        OR (NOT secret_sync_order_from_event AND secret_sync_target_order < 0)
    ),
    ADD CONSTRAINT outbox_secret_sync_receiver_effect_state_chk CHECK (
        secret_sync_receiver_effect_state IN ('none', 'effect_possible', 'failure_authorized')
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
                OR (secret_sync_receiver_effect_state = 'failure_authorized'
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

-- online-safe: the documented fleet-stop gate makes this short blocking build
-- intentional, and keeping it in this transaction makes target order authoritative
-- before any new writer can restart.
CREATE UNIQUE INDEX secret_sync_jobs_target_order_idx
    ON secret_sync_jobs (tenant_id, target, target_order);

-- online-safe: same explicit fleet-stop gate as the paired unique index above.
CREATE INDEX outbox_secret_sync_target_order_idx
    ON outbox (tenant_id, destination, secret_sync_target_order)
    WHERE left(destination, 12) = 'secret.sync.';

-- online-safe: the same fleet stop makes duplicate preflight plus this blocking
-- receiver-key fence atomic with the order backfill. Rebuild can now attach at
-- most one retained command for an immutable tenant-scoped idempotency key.
CREATE UNIQUE INDEX outbox_secret_sync_idempotency_idx
    ON outbox (tenant_id, idempotency_key)
    WHERE left(destination, 12) = 'secret.sync.';

-- Terminal evidence is projected only through the owner-role projection path.
-- The application role can enqueue and read jobs, but cannot forge a pending ->
-- terminal transition with plausible-looking receipt fields.
REVOKE UPDATE ON secret_sync_jobs FROM trstctl_app;

CREATE FUNCTION secret_sync_guard_job_order()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
	legacy_receipt_upgrade boolean;
BEGIN
	IF TG_OP = 'INSERT' THEN
		IF NEW.status <> 'pending' AND current_user = 'trstctl_app' THEN
			RAISE EXCEPTION USING
				ERRCODE = '55000',
				MESSAGE = 'application role may insert only pending event-projected secret-sync jobs';
		END IF;
		RETURN NEW;
	END IF;

	legacy_receipt_upgrade :=
		OLD.status IN ('failed', 'delivered')
		AND OLD.terminal_event_from_event IS FALSE
		AND NEW.terminal_event_from_event IS TRUE
		AND current_user <> 'trstctl_app'
		AND NEW.status IS NOT DISTINCT FROM OLD.status
		AND NEW.attempts IS NOT DISTINCT FROM OLD.attempts
		AND NEW.remote_version IS NOT DISTINCT FROM OLD.remote_version
		AND NEW.last_error IS NOT DISTINCT FROM OLD.last_error
		AND NEW.delivered_at IS NOT DISTINCT FROM OLD.delivered_at
		AND NEW.updated_at IS NOT DISTINCT FROM OLD.updated_at
		AND NEW.terminal_event_id <> ''
		AND NEW.terminal_event_type = 'secret.sync.' || NEW.status
		AND NEW.terminal_event_sequence > 0
		AND NEW.terminal_event_digest ~ '^[0-9a-f]{64}$';

	-- The first terminal event is canonical. An exact replay may write the same
    -- values, but a second retained event (including one with the same status)
    -- must not rewrite attempts, receiver evidence, error, or event time.
    IF OLD.status IN ('failed', 'delivered')
       AND (
           NEW.status IS DISTINCT FROM OLD.status
           OR NEW.attempts IS DISTINCT FROM OLD.attempts
           OR NEW.remote_version IS DISTINCT FROM OLD.remote_version
           OR NEW.last_error IS DISTINCT FROM OLD.last_error
           OR NEW.delivered_at IS DISTINCT FROM OLD.delivered_at
           OR NEW.updated_at IS DISTINCT FROM OLD.updated_at
           OR NEW.terminal_event_id IS DISTINCT FROM OLD.terminal_event_id
           OR NEW.terminal_event_type IS DISTINCT FROM OLD.terminal_event_type
           OR NEW.terminal_event_sequence IS DISTINCT FROM OLD.terminal_event_sequence
           OR NEW.terminal_event_digest IS DISTINCT FROM OLD.terminal_event_digest
           OR NEW.terminal_event_from_event IS DISTINCT FROM OLD.terminal_event_from_event
       ) AND NOT legacy_receipt_upgrade THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'terminal secret-sync job evidence is immutable';
    END IF;

    -- A new terminal transition must carry the exact immutable event receipt.
    -- A bare UPDATE (including one preceded by a forged custom GUC) cannot remove
    -- a FIFO barrier. The projection sink additionally validates deterministic
    -- event identity/type/sequence/digest before writing these fields.
    IF OLD.status = 'pending'
       AND NEW.status IN ('failed', 'delivered')
       AND (
           NEW.terminal_event_id = ''
           OR NEW.terminal_event_type <> 'secret.sync.' || NEW.status
           OR NEW.terminal_event_sequence IS NULL
           OR NEW.terminal_event_sequence <= 0
           OR NEW.terminal_event_digest !~ '^[0-9a-f]{64}$'
           OR NEW.terminal_event_from_event IS DISTINCT FROM true
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'secret-sync terminal transition requires event-projection authority';
    END IF;

    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.tenant_epoch IS DISTINCT FROM OLD.tenant_epoch
       OR NEW.target IS DISTINCT FROM OLD.target
       OR NEW.target_order IS DISTINCT FROM OLD.target_order THEN
        RAISE EXCEPTION USING
            ERRCODE = '27000',
            MESSAGE = 'secret-sync target order is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER secret_sync_guard_job_order
BEFORE INSERT OR UPDATE OF tenant_id, tenant_epoch, target, target_order, status, attempts, remote_version, last_error, delivered_at, updated_at,
                 terminal_event_id, terminal_event_type, terminal_event_sequence, terminal_event_digest, terminal_event_from_event
ON secret_sync_jobs
FOR EACH ROW
EXECUTE FUNCTION secret_sync_guard_job_order();

CREATE FUNCTION secret_sync_guard_active_job_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
	IF EXISTS (SELECT 1 FROM tenants WHERE tenant_id = OLD.tenant_id) THEN
		RAISE EXCEPTION USING
			ERRCODE = '55000',
			MESSAGE = 'secret-sync job deletion requires tenant offboarding';
	END IF;
	RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER secret_sync_guard_active_job_delete
AFTER DELETE ON secret_sync_jobs
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION secret_sync_guard_active_job_delete();

CREATE FUNCTION secret_sync_guard_outbox_order()
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
	       OR OLD.secret_sync_receiver_effect_state = 'failure_authorized'
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

CREATE TRIGGER secret_sync_guard_outbox_order
BEFORE INSERT OR UPDATE OF tenant_id, destination, secret_sync_target_order, secret_sync_order_from_event,
                        secret_sync_receiver_effect_state, secret_sync_receiver_io_starts,
                        secret_sync_failure_detail, secret_sync_failure_attempts ON outbox
FOR EACH ROW
EXECUTE FUNCTION secret_sync_guard_outbox_order();

CREATE FUNCTION secret_sync_guard_outbox_state()
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
	                  AND NEW.secret_sync_receiver_effect_state = 'effect_possible')
	              OR
	              (terminal_job.status = 'failed'
	                  AND (
	                      (NEW.secret_sync_receiver_effect_state = 'failure_authorized'
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
	          AND NEW.secret_sync_receiver_effect_state = 'failure_authorized'
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
	               AND older_outbox.secret_sync_receiver_effect_state = 'effect_possible'
	               AND older_outbox.secret_sync_receiver_io_starts = 1)
	           OR
	           (older_job.status = 'failed'
	               AND older_outbox.secret_sync_receiver_effect_state = 'failure_authorized'
	               AND older_outbox.secret_sync_receiver_io_starts BETWEEN 0 AND 1
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

CREATE TRIGGER secret_sync_guard_outbox_state
BEFORE UPDATE OF status ON outbox
FOR EACH ROW
EXECUTE FUNCTION secret_sync_guard_outbox_state();

-- A tenant offboard deletes the tenant row in the same transaction. Any other
-- deletion of an active command would erase its FIFO barrier, so a deferred check
-- rejects it after all statements in the transaction have completed.
CREATE FUNCTION secret_sync_guard_active_outbox_delete()
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
	                              AND OLD.secret_sync_receiver_effect_state = 'effect_possible'
	                              AND OLD.secret_sync_receiver_io_starts = 1)
	                          OR
	                          (terminal_job.status = 'failed'
	                              AND OLD.secret_sync_receiver_effect_state = 'failure_authorized'
	                              AND OLD.secret_sync_receiver_io_starts BETWEEN 0 AND 1
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

CREATE CONSTRAINT TRIGGER secret_sync_guard_active_outbox_delete
AFTER DELETE ON outbox
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION secret_sync_guard_active_outbox_delete();
