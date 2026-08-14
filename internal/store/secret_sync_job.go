// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SecretSyncJobStatus is the projected delivery state of one secret-sync outbox
// intent.
type SecretSyncJobStatus string

const (
	SecretSyncJobPending   SecretSyncJobStatus = "pending"
	SecretSyncJobDelivered SecretSyncJobStatus = "delivered"
	SecretSyncJobFailed    SecretSyncJobStatus = "failed"
)

// SecretSyncReceiverEffectState is durable command-global authority for deciding
// whether a secret.sync.failed event is safe. It is deliberately separate from
// outbox attempts: a later claim cannot forget that an expired generation may
// already have reached the receiver.
type SecretSyncReceiverEffectState string

const (
	SecretSyncReceiverNoEffect          SecretSyncReceiverEffectState = "none"
	SecretSyncReceiverEffectPossible    SecretSyncReceiverEffectState = "effect_possible"
	SecretSyncReceiverFailureAuthorized SecretSyncReceiverEffectState = "failure_authorized"
)

// SecretSyncReceiverAuthority is the tenant-scoped durable receiver boundary for
// one command. ReceiverIOStarts is monotonic and counts every worker generation
// authorized to start the same idempotent receiver operation.
type SecretSyncReceiverAuthority struct {
	OutboxID         int64
	JobStatus        SecretSyncJobStatus
	OutboxStatus     string
	OutboxAttempts   int
	EffectState      SecretSyncReceiverEffectState
	ReceiverIOStarts int64
	FailureDetail    string
	FailureAttempts  int
}

// SecretSyncJob is delivery evidence for one version of one secret sent to one
// configured target. ValueDigest may be used for drift comparison, but the secret
// value itself is never persisted here; the encrypted outbox payload remains the
// delivery authority (AN-6, AN-8).
type SecretSyncJob struct {
	ID                     string
	TenantID               string
	TenantEpoch            string
	SecretName             string
	SecretVersion          int64
	Target                 string
	RemoteKey              string
	ValueDigest            string
	Status                 SecretSyncJobStatus
	OutboxID               int64
	TargetOrder            int64
	Attempts               int
	RemoteVersion          string
	LastError              string
	IdempotencyKey         string
	RequestBinding         string
	TerminalEventID        string
	TerminalEventType      string
	TerminalEventSequence  *int64
	TerminalEventDigest    string
	TerminalEventFromEvent *bool
	RequestedAt            time.Time
	UpdatedAt              time.Time
	DeliveredAt            *time.Time
}

// SecretSyncTerminalHistoryRow is the cross-tenant startup/rebuild inventory used
// to prove that a SQL terminal fact still has one canonical retained AN-2 event.
// OutboxPresent may be false only for event-derived rows whose delivered cleanup
// record was reclaimed by retention GC. Migration-derived negative FIFO fences
// remain paired with their outbox row until tenant offboarding.
type SecretSyncTerminalHistoryRow struct {
	Job                   SecretSyncJob
	OutboxPresent         bool
	OutboxDestination     string
	OutboxStatus          string
	OutboxTargetOrder     int64
	OutboxOrderFromEvent  *bool
	OutboxEffectState     SecretSyncReceiverEffectState
	OutboxReceiverStarts  int64
	OutboxFailureDetail   string
	OutboxFailureAttempts int
}

// ListSecretSyncTerminalHistoryRows returns the owner-role inventory needed by
// the global history validator. It is intentionally system-scoped: startup and a
// full rebuild must detect disagreement in any tenant before workers resume.
func (s *Store) ListSecretSyncTerminalHistoryRows(ctx context.Context) ([]SecretSyncTerminalHistoryRow, error) {
	//trstctl:system-query — cross-tenant by design: startup/rebuild inventories only terminal secret-sync receipts and their non-secret outbox metadata so every tenant's FIFO release can be checked against retained AN-2 history before any worker resumes.
	rows, err := s.SystemPool().Query(ctx, `
		SELECT job.id, job.tenant_id::text, job.tenant_epoch, job.secret_name,
		       job.secret_version, job.target, job.remote_key, job.value_digest,
		       job.status, job.outbox_id, job.target_order, job.attempts,
		       job.remote_version, job.last_error, job.idempotency_key,
		       job.request_binding, job.requested_at, job.terminal_event_id,
		       job.terminal_event_type, job.terminal_event_sequence,
		       job.terminal_event_digest, job.terminal_event_from_event,
		       job.updated_at, job.delivered_at,
		       queued.id IS NOT NULL,
		       COALESCE(queued.destination, ''), COALESCE(queued.status, ''),
		       COALESCE(queued.secret_sync_target_order, 0),
		       queued.secret_sync_order_from_event,
		       COALESCE(queued.secret_sync_receiver_effect_state, ''),
		       COALESCE(queued.secret_sync_receiver_io_starts, 0),
		       COALESCE(queued.secret_sync_failure_detail, ''),
		       COALESCE(queued.secret_sync_failure_attempts, 0)
		  FROM secret_sync_jobs AS job
		  LEFT JOIN outbox AS queued
		    ON queued.tenant_id = job.tenant_id AND queued.id = job.outbox_id
		 WHERE job.status IN ('delivered', 'failed')
		 ORDER BY job.tenant_id, job.id`)
	if err != nil {
		return nil, fmt.Errorf("store: list secret-sync terminal history: %w", err)
	}
	defer rows.Close()
	var out []SecretSyncTerminalHistoryRow
	for rows.Next() {
		var item SecretSyncTerminalHistoryRow
		if err := rows.Scan(
			&item.Job.ID, &item.Job.TenantID, &item.Job.TenantEpoch,
			&item.Job.SecretName, &item.Job.SecretVersion, &item.Job.Target,
			&item.Job.RemoteKey, &item.Job.ValueDigest, &item.Job.Status,
			&item.Job.OutboxID, &item.Job.TargetOrder, &item.Job.Attempts,
			&item.Job.RemoteVersion, &item.Job.LastError, &item.Job.IdempotencyKey,
			&item.Job.RequestBinding, &item.Job.RequestedAt,
			&item.Job.TerminalEventID, &item.Job.TerminalEventType,
			&item.Job.TerminalEventSequence, &item.Job.TerminalEventDigest,
			&item.Job.TerminalEventFromEvent, &item.Job.UpdatedAt,
			&item.Job.DeliveredAt, &item.OutboxPresent, &item.OutboxDestination,
			&item.OutboxStatus, &item.OutboxTargetOrder,
			&item.OutboxOrderFromEvent, &item.OutboxEffectState,
			&item.OutboxReceiverStarts, &item.OutboxFailureDetail,
			&item.OutboxFailureAttempts,
		); err != nil {
			return nil, fmt.Errorf("store: scan secret-sync terminal history: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate secret-sync terminal history: %w", err)
	}
	return out, nil
}

// ReconcileSecretSyncLegacyTerminalReceipt replaces migration 0153's synthetic
// receipt with the exact retained event receipt. The WHERE clause repeats every
// immutable terminal fact, so concurrent drift cannot be blessed accidentally.
func (s *Store) ReconcileSecretSyncLegacyTerminalReceipt(
	ctx context.Context,
	event SecretSyncTerminalEvent,
) error {
	if event.TenantID == "" || event.TenantEpoch == "" || event.JobID == "" ||
		event.EventSequence <= 0 || len(event.PayloadDigest) != 64 {
		return errors.New("store: legacy secret-sync receipt reconciliation is incomplete")
	}
	deliveredAt := any(nil)
	remoteVersion := ""
	lastError := event.LastError
	if event.Status == SecretSyncJobDelivered {
		deliveredAt = event.OccurredAt
		remoteVersion = event.RemoteVersion
		lastError = ""
	}
	return s.WithTenantProjection(ctx, event.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE secret_sync_jobs
			   SET terminal_event_id = $9, terminal_event_type = $10,
			       terminal_event_sequence = $11, terminal_event_digest = $12,
			       terminal_event_from_event = true
			 WHERE tenant_id = $1 AND tenant_epoch = $13 AND id = $2
			   AND status = $3 AND attempts = $4 AND remote_version = $5
			   AND last_error = $6 AND delivered_at IS NOT DISTINCT FROM $7::timestamptz
			   AND updated_at = $8 AND terminal_event_from_event = false`,
			event.TenantID, event.JobID, event.Status, event.Attempts,
			remoteVersion, lastError, deliveredAt, event.OccurredAt,
			event.EventID, event.EventType, event.EventSequence,
			event.PayloadDigest, event.TenantEpoch)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: legacy secret-sync terminal receipt changed during reconciliation", ErrIdempotencyConflict)
		}
		return nil
	})
}

// ApplySecretSyncJobQueuedTx projects a secret.sync.queued event. The caller
// enqueues OutboxID in the same transaction as this projection (AN-6). A duplicate
// event is a no-op, so it cannot regress later delivery evidence back to pending.
func (s *Store) ApplySecretSyncJobQueuedTx(ctx context.Context, tx pgx.Tx, job SecretSyncJob) error {
	return s.applySecretSyncJobQueuedTx(ctx, tx, job, false)
}

// applySecretSyncJobQueuedTx accepts a negative order only after the caller has
// authenticated it against one retained migration-derived outbox row. New event
// projections always use ApplySecretSyncJobQueuedTx and therefore remain strictly
// positive.
func (s *Store) applySecretSyncJobQueuedTx(ctx context.Context, tx pgx.Tx, job SecretSyncJob, allowLegacyNegative bool) error {
	if job.TenantEpoch == "" || job.TargetOrder == 0 || (!allowLegacyNegative && job.TargetOrder < 0) {
		return fmt.Errorf("store: secret-sync job requires a tenant epoch and positive event target order")
	}
	updatedAt := job.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = job.RequestedAt
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO secret_sync_jobs
		        (tenant_id, tenant_epoch, id, secret_name, secret_version, target, remote_key,
		         value_digest, status, outbox_id, target_order, attempts, remote_version,
		         last_error, idempotency_key, request_binding, requested_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, $10, 0, '', '', $11, $12, $13, $14)
		 ON CONFLICT (tenant_id, id) DO NOTHING`,
		job.TenantID, job.TenantEpoch, job.ID, job.SecretName, job.SecretVersion, job.Target,
		job.RemoteKey, job.ValueDigest, job.OutboxID, job.TargetOrder, job.IdempotencyKey, job.RequestBinding,
		job.RequestedAt, updatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exact bool
	if err := tx.QueryRow(ctx, `
		SELECT tenant_epoch = $3
		   AND secret_name = $4
		   AND secret_version = $5
		   AND target = $6
		   AND remote_key = $7
		   AND value_digest = $8
		   AND outbox_id = $9
		   AND target_order = $10
		   AND idempotency_key = $11
		   AND request_binding = $12
		  FROM secret_sync_jobs
		 WHERE tenant_id = $1 AND id = $2`,
		job.TenantID, job.ID, job.TenantEpoch, job.SecretName, job.SecretVersion,
		job.Target, job.RemoteKey, job.ValueDigest, job.OutboxID, job.TargetOrder,
		job.IdempotencyKey, job.RequestBinding).Scan(&exact); err != nil {
		return err
	}
	if !exact {
		return fmt.Errorf("%w: secret-sync job %s", ErrIdempotencyConflict, job.ID)
	}
	return nil
}

// SecretSyncTerminalEvent is the immutable AN-2 receipt that authorizes the
// first pending -> terminal transition. PayloadDigest is SHA-256 over the exact
// retained event payload; the projector is the only production constructor.
type SecretSyncTerminalEvent struct {
	TenantID      string
	TenantEpoch   string
	JobID         string
	Status        SecretSyncJobStatus
	Attempts      int
	RemoteVersion string
	LastError     string
	OccurredAt    time.Time
	EventID       string
	EventType     string
	EventSequence int64
	PayloadDigest string
	// FailureDefinitelyNoEffect is projection provenance, not a caller guess.
	// It is true only for the current typed failure schema whose producer first
	// froze durable no-network authority. Legacy v1 failure events used the same
	// event type for arbitrary retry exhaustion and therefore remain ambiguous.
	FailureDefinitelyNoEffect bool
}

// ApplySecretSyncTerminalEventTx projects one canonical delivered/failed event.
// Exact replay is a no-op; same-status drift and the opposite outcome both fail.
func (s *Store) ApplySecretSyncTerminalEventTx(ctx context.Context, tx pgx.Tx, event SecretSyncTerminalEvent) error {
	if event.TenantID == "" || event.TenantEpoch == "" || event.JobID == "" || event.Attempts < 1 || event.EventSequence <= 0 ||
		len(event.PayloadDigest) != 64 || event.OccurredAt.IsZero() {
		return fmt.Errorf("store: secret-sync terminal event is incomplete")
	}
	wantID, wantType := "", ""
	switch event.Status {
	case SecretSyncJobDelivered:
		if event.FailureDefinitelyNoEffect {
			return fmt.Errorf("store: delivered secret-sync event carries failure provenance")
		}
		wantID = SecretSyncDeliveredEventID(event.TenantID, event.JobID)
		wantType = "secret.sync.delivered"
	case SecretSyncJobFailed:
		wantID = SecretSyncFailedEventID(event.TenantID, event.JobID)
		wantType = "secret.sync.failed"
		if event.LastError == "" {
			return fmt.Errorf("store: failed secret-sync event requires a closed error")
		}
	default:
		return fmt.Errorf("store: secret-sync terminal status %q is invalid", event.Status)
	}
	if event.EventID != wantID || event.EventType != wantType {
		return fmt.Errorf("%w: secret-sync terminal event identity differs", ErrIdempotencyConflict)
	}

	deliveredAt := any(nil)
	remoteVersion := ""
	lastError := event.LastError
	if event.Status == SecretSyncJobDelivered {
		deliveredAt = event.OccurredAt
		remoteVersion = event.RemoteVersion
		lastError = ""
	}
	tag, err := tx.Exec(ctx,
		`UPDATE secret_sync_jobs
		    SET status = $3, attempts = $4, remote_version = $5, last_error = $6,
		        delivered_at = $7, updated_at = $8,
		        terminal_event_id = $9, terminal_event_type = $10,
		        terminal_event_sequence = $11, terminal_event_digest = $12,
		        terminal_event_from_event = true
		  WHERE tenant_id = $1 AND tenant_epoch = $13 AND id = $2
		    AND (
		        status = 'pending'
		        OR (
		            status = $3 AND attempts = $4 AND remote_version = $5
		            AND last_error = $6 AND delivered_at IS NOT DISTINCT FROM $7::timestamptz
		            AND updated_at = $8 AND terminal_event_id = $9
		            AND terminal_event_type = $10 AND terminal_event_sequence = $11
		            AND terminal_event_digest = $12 AND terminal_event_from_event
		        )
		    )`,
		event.TenantID, event.JobID, event.Status, event.Attempts, remoteVersion, lastError,
		deliveredAt, event.OccurredAt, event.EventID, event.EventType, event.EventSequence,
		event.PayloadDigest, event.TenantEpoch)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		effectState := SecretSyncReceiverFailureAuthorized
		minimumReceiverStarts := int64(0)
		failureDetail := event.LastError
		failureAttempts := event.Attempts
		if event.Status == SecretSyncJobDelivered {
			effectState = SecretSyncReceiverEffectPossible
			minimumReceiverStarts = 1
			failureDetail = ""
			failureAttempts = 0
		} else if !event.FailureDefinitelyNoEffect {
			// A v1 failure could have been emitted after any number of external
			// attempts. Preserve at least the retained attempt count as sticky
			// effect-possible authority; only a current typed no-network proof may
			// release successors as failure_authorized.
			effectState = SecretSyncReceiverEffectPossible
			minimumReceiverStarts = int64(event.Attempts)
			failureDetail = ""
			failureAttempts = 0
		}
		// A current failure event proves its producer froze no-network authority
		// before append only when the retained SQL state is still none or already
		// failure_authorized. An existing effect_possible row is stronger recovery
		// evidence: it can come from a pre-0153 artifact or an older worker
		// generation. Event replay must keep that ambiguity sticky; only the
		// worker's pre-append authorization CAS may ever convert it.
		outboxTag, err := tx.Exec(ctx, `
			UPDATE outbox AS queued
			   SET secret_sync_receiver_effect_state = CASE
			           WHEN $6 = 'failed'
			            AND queued.secret_sync_receiver_effect_state = 'effect_possible'
			           THEN 'effect_possible'
			           ELSE $4
			       END,
			       secret_sync_receiver_io_starts = GREATEST(
			           queued.secret_sync_receiver_io_starts,
			           CASE
			               WHEN $6 = 'failed'
			                AND queued.secret_sync_receiver_effect_state = 'effect_possible'
			               THEN $9::bigint
			               ELSE $5::bigint
			           END
			       ),
			       secret_sync_failure_detail = CASE
			           WHEN $6 = 'failed'
			            AND queued.secret_sync_receiver_effect_state = 'effect_possible'
			           THEN ''
			           ELSE $7
			       END,
			       secret_sync_failure_attempts = CASE
			           WHEN $6 = 'failed'
			            AND queued.secret_sync_receiver_effect_state = 'effect_possible'
			           THEN 0
			           ELSE $8
			       END
			  FROM secret_sync_jobs AS job
			 WHERE job.tenant_id = $1 AND job.tenant_epoch = $3 AND job.id = $2
			   AND job.status = $6
			   AND queued.tenant_id = job.tenant_id
			   AND queued.id = job.outbox_id
			   AND queued.destination = 'secret.sync.' || job.target
			   AND queued.secret_sync_target_order = job.target_order`,
			event.TenantID, event.JobID, event.TenantEpoch, effectState,
			minimumReceiverStarts, event.Status, failureDetail,
			failureAttempts, event.Attempts)
		if err != nil {
			return err
		}
		if outboxTag.RowsAffected() == 0 {
			var mismatchedOutbox bool
			if err := tx.QueryRow(ctx, `
				SELECT EXISTS (
				    SELECT 1
				      FROM secret_sync_jobs AS job
				      JOIN outbox AS queued
				        ON queued.tenant_id = job.tenant_id
				       AND queued.id = job.outbox_id
				     WHERE job.tenant_id = $1 AND job.tenant_epoch = $3 AND job.id = $2
				)`, event.TenantID, event.JobID, event.TenantEpoch).Scan(&mismatchedOutbox); err != nil {
				return err
			}
			if mismatchedOutbox {
				return fmt.Errorf("%w: secret-sync terminal outbox authority differs", ErrIdempotencyConflict)
			}
		}
		return nil
	}
	var status SecretSyncJobStatus
	if err := tx.QueryRow(ctx,
		`SELECT status FROM secret_sync_jobs WHERE tenant_id = $1 AND tenant_epoch = $3 AND id = $2`,
		event.TenantID, event.JobID, event.TenantEpoch).Scan(&status); err != nil {
		return err
	}
	return fmt.Errorf("%w: canonical secret-sync terminal evidence is %s, incoming is %s",
		ErrIdempotencyConflict, status, event.Status)
}

// GetSecretSyncJob returns one sync job in its tenant's RLS context.
func (s *Store) GetSecretSyncJob(ctx context.Context, tenantID, jobID string) (SecretSyncJob, error) {
	var job SecretSyncJob
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanSecretSyncJob(tx.QueryRow(ctx,
			`SELECT id, tenant_id::text, tenant_epoch, secret_name, secret_version, target,
			        remote_key, value_digest, status, outbox_id, target_order, attempts,
			        remote_version, last_error, idempotency_key, request_binding, requested_at,
			        terminal_event_id, terminal_event_type, terminal_event_sequence,
			        terminal_event_digest, terminal_event_from_event,
			        updated_at, delivered_at
			   FROM secret_sync_jobs
			  WHERE tenant_id = $1 AND id = $2`,
			tenantID, jobID), &job)
	})
	return job, err
}

// GetLatestSecretSyncJob returns the newest delivery evidence for the named
// source secret and remote destination. It is useful for drift/status surfaces.
func (s *Store) GetLatestSecretSyncJob(ctx context.Context, tenantID, secretName, target, remoteKey string) (SecretSyncJob, error) {
	var job SecretSyncJob
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanSecretSyncJob(tx.QueryRow(ctx,
			`SELECT id, tenant_id::text, tenant_epoch, secret_name, secret_version, target,
			        remote_key, value_digest, status, outbox_id, target_order, attempts,
			        remote_version, last_error, idempotency_key, request_binding, requested_at,
			        terminal_event_id, terminal_event_type, terminal_event_sequence,
			        terminal_event_digest, terminal_event_from_event,
			        updated_at, delivered_at
			   FROM secret_sync_jobs
			  WHERE tenant_id = $1 AND secret_name = $2 AND target = $3 AND remote_key = $4
			  ORDER BY requested_at DESC, id DESC
			  LIMIT 1`,
			tenantID, secretName, target, remoteKey), &job)
	})
	return job, err
}

// ListSecretSyncJobsPage returns a bounded id-keyset page for one tenant. Empty
// target/status filters mean all targets/statuses.
func (s *Store) ListSecretSyncJobsPage(ctx context.Context, tenantID, target string, status SecretSyncJobStatus, afterID string, limit int) ([]SecretSyncJob, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("store: ListSecretSyncJobsPage requires a tenant id (AN-1)")
	}
	if limit <= 0 {
		return nil, fmt.Errorf("store: ListSecretSyncJobsPage requires a positive limit")
	}
	var out []SecretSyncJob
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id::text, tenant_epoch, secret_name, secret_version, target,
			        remote_key, value_digest, status, outbox_id, target_order, attempts,
			        remote_version, last_error, idempotency_key, request_binding, requested_at,
			        terminal_event_id, terminal_event_type, terminal_event_sequence,
			        terminal_event_digest, terminal_event_from_event,
			        updated_at, delivered_at
			   FROM secret_sync_jobs
			  WHERE tenant_id = $1 AND id > $2
			    AND ($3 = '' OR target = $3)
			    AND ($4 = '' OR status = $4)
			  ORDER BY id
			  LIMIT $5`,
			tenantID, afterID, target, string(status), limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var job SecretSyncJob
			if err := scanSecretSyncJob(rows, &job); err != nil {
				return err
			}
			out = append(out, job)
		}
		return rows.Err()
	})
	return out, err
}

func scanSecretSyncJob(row rowScanner, job *SecretSyncJob) error {
	return row.Scan(
		&job.ID, &job.TenantID, &job.TenantEpoch, &job.SecretName, &job.SecretVersion, &job.Target,
		&job.RemoteKey, &job.ValueDigest, &job.Status, &job.OutboxID, &job.TargetOrder, &job.Attempts,
		&job.RemoteVersion, &job.LastError, &job.IdempotencyKey, &job.RequestBinding, &job.RequestedAt,
		&job.TerminalEventID, &job.TerminalEventType, &job.TerminalEventSequence,
		&job.TerminalEventDigest, &job.TerminalEventFromEvent,
		&job.UpdatedAt, &job.DeliveredAt,
	)
}

var secretSyncJobNamespace = uuid.MustParse("dc064ff8-bcd7-5ac1-a310-65cb5ccf3cc1")
var secretSyncEventNamespace = uuid.MustParse("8dfda7f4-9293-55f0-b2fe-642a43276964")

// DurableSecretSyncJobID is the stable tenant + raw Idempotency-Key identity
// shared by the API and event producer. Looking it up avoids opening the current
// source secret on a replay after the short-lived response recorder is collected.
func DurableSecretSyncJobID(tenantID, idempotencyKey string) string {
	return "sync-" + uuid.NewSHA1(secretSyncJobNamespace, []byte(tenantID+"\x00"+idempotencyKey)).String()
}

// DurableSecretSyncJobIDForEpoch binds a new standalone command to one tenant
// registration lifecycle. Re-registering the same tenant UUID therefore cannot
// reactivate retained pre-offboard command or evidence identities.
func DurableSecretSyncJobIDForEpoch(tenantID, tenantEpoch, idempotencyKey string) string {
	return "sync-" + uuid.NewSHA1(secretSyncJobNamespace, []byte(tenantID+"\x00"+tenantEpoch+"\x00"+idempotencyKey)).String()
}

// SecretSyncQueuedEventID is the deterministic producer identity of one queued
// command. jobID already includes the tenant lifecycle epoch for new commands.
func SecretSyncQueuedEventID(tenantID, jobID string) string {
	return "secret-sync-event-" + uuid.NewSHA1(secretSyncEventNamespace, []byte("queued\x00"+tenantID+"\x00"+jobID)).String()
}

// SecretSyncDeliveredEventID and SecretSyncFailedEventID are the only accepted
// terminal producer identities. The two names stay distinct so contradictory
// retained outcomes can be detected and rejected instead of resolved by replay
// order.
func SecretSyncDeliveredEventID(tenantID, jobID string) string {
	return "secret-sync-delivered-" + uuid.NewSHA1(secretSyncEventNamespace, []byte(tenantID+"\x00"+jobID)).String()
}

func SecretSyncFailedEventID(tenantID, jobID string) string {
	return "secret-sync-failed-" + uuid.NewSHA1(secretSyncEventNamespace, []byte(tenantID+"\x00"+jobID)).String()
}

// WithSecretSyncTerminalChoiceLock serializes the first delivered-vs-failed
// choice for one job across control-plane replicas. It first holds the shared
// tenant-lifecycle side on the same session, then takes the terminal-choice lock.
// BeginSecretSyncReceiverIO uses the identical lifecycle -> terminal order inside
// its short transaction, so an offboard and a terminal publisher cannot form an
// inverse-lock deadlock.
func (s *Store) WithSecretSyncTerminalChoiceLock(
	ctx context.Context,
	tenantID, jobID string,
	fn func(context.Context) error,
) error {
	if tenantID == "" || jobID == "" || fn == nil {
		return errors.New("store: secret-sync terminal choice lock is incomplete")
	}
	conn, err := s.SystemPool().Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquire secret-sync terminal-choice connection: %w", err)
	}
	defer conn.Release()
	lifecycleName := tenantLifecycleLockName(tenantID)
	if _, err := conn.Exec(ctx,
		`SELECT pg_advisory_lock_shared(hashtextextended($1, 0))`, lifecycleName); err != nil {
		return fmt.Errorf("store: acquire shared secret-sync lifecycle connection lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(),
			`SELECT pg_advisory_unlock_shared(hashtextextended($1, 0))`, lifecycleName)
	}()
	lockName := secretSyncTerminalChoiceLockName(tenantID, jobID)
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, lockName); err != nil {
		return fmt.Errorf("store: acquire secret-sync terminal-choice lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, lockName)
	}()
	return fn(ctx)
}

func secretSyncTerminalChoiceLockName(tenantID, jobID string) string {
	return "secret-sync-terminal-choice\x1f" + tenantID + "\x1f" + jobID
}

func lockSecretSyncTerminalChoiceTx(ctx context.Context, tx pgx.Tx, tenantID, jobID string) error {
	if tenantID == "" || jobID == "" {
		return errors.New("store: secret-sync terminal choice transaction lock is incomplete")
	}
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		secretSyncTerminalChoiceLockName(tenantID, jobID)); err != nil {
		return fmt.Errorf("store: acquire secret-sync terminal-choice transaction lock: %w", err)
	}
	return nil
}

// SecretSyncReceiverAuthority returns the durable command-global receiver state.
// It is tenant scoped and contains no secret payload bytes.
func (s *Store) SecretSyncReceiverAuthority(ctx context.Context, tenantID, jobID string) (SecretSyncReceiverAuthority, error) {
	if tenantID == "" || jobID == "" {
		return SecretSyncReceiverAuthority{}, errors.New("store: secret-sync receiver authority is incomplete")
	}
	var authority SecretSyncReceiverAuthority
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanSecretSyncReceiverAuthority(tx.QueryRow(ctx, `
			SELECT queued.id, job.status, queued.status, queued.attempts,
			       queued.secret_sync_receiver_effect_state,
			       queued.secret_sync_receiver_io_starts,
			       queued.secret_sync_failure_detail,
			       queued.secret_sync_failure_attempts
			  FROM secret_sync_jobs AS job
			  JOIN outbox AS queued
			    ON queued.tenant_id = job.tenant_id
			   AND queued.id = job.outbox_id
			   AND queued.destination = 'secret.sync.' || job.target
			   AND queued.secret_sync_target_order = job.target_order
			 WHERE job.tenant_id = $1 AND job.id = $2`, tenantID, jobID), &authority)
	})
	return authority, err
}

// BeginSecretSyncReceiverIO advances the sticky receiver boundary immediately
// before one worker generation calls its target. It owns the transaction-scoped
// terminal-choice lock itself; callers must not wrap it in the session form. The
// retained-history guard receives the exact live registration while its shared
// lifecycle fence is still held, so it can reject a retained offboard that won
// Append even when that offboard's SQL projection rolled back.
func (s *Store) BeginSecretSyncReceiverIO(
	ctx context.Context,
	tenantID, tenantEpoch, jobID string,
	outboxID int64,
	retainedHistoryGuard func(context.Context, TenantRegistrationSnapshot) error,
) (token int64, proceed bool, err error) {
	if tenantID == "" || tenantEpoch == "" || jobID == "" || outboxID <= 0 {
		return 0, false, errors.New("store: begin secret-sync receiver I/O is incomplete")
	}
	err = s.WithTenantProjection(ctx, tenantID, func(tx pgx.Tx) error {
		// Lock order is lifecycle -> terminal choice -> tenant row -> epoch ->
		// receiver rows. The transaction ends before Target.DeliverOperation, so
		// no pooled connection waits behind connector I/O.
		if err := lockTenantLifecycleSharedTx(ctx, tx, tenantID); err != nil {
			return err
		}
		var recoveryAuthorized bool
		//trstctl:system-query — the cross-tenant system singleton carries no tenant data; checking it inside receiver start makes an event-only restore a global no-I/O fence (AN-1 exemption).
		if err := tx.QueryRow(ctx, `
			SELECT receiver_io_authorized
			  FROM secret_sync_recovery_authority
			 WHERE singleton`).Scan(&recoveryAuthorized); err != nil {
			return fmt.Errorf("store: read secret-sync recovery authority before receiver I/O: %w", err)
		}
		if !recoveryAuthorized {
			return ErrSecretSyncReceiverRecoveryFenced
		}
		if err := lockSecretSyncTerminalChoiceTx(ctx, tx, tenantID, jobID); err != nil {
			return err
		}
		registration, err := lockLiveTenantRegistrationSnapshotAfterLifecycleTx(ctx, tx, tenantID)
		if err != nil {
			if errors.Is(err, ErrApplicationSecretTenantEpochMismatch) {
				return nil
			}
			return err
		}
		if err := validateApplicationSecretTenantEpochAfterLifecycleTx(ctx, tx, tenantID, tenantEpoch); err != nil {
			if errors.Is(err, ErrApplicationSecretTenantEpochMismatch) {
				return nil
			}
			return err
		}
		// Pin the exact job/outbox pair before consulting retained history. The
		// guard is the final read between those row locks and the receiver-start
		// CAS, so neither a terminal projection nor an outbox finalizer can change
		// the SQL authority underneath that fixed history decision.
		var authority SecretSyncReceiverAuthority
		if err := loadSecretSyncReceiverAuthorityTx(
			ctx, tx, tenantID, jobID, outboxID, &authority,
		); errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		if retainedHistoryGuard != nil {
			if err := retainedHistoryGuard(ctx, registration); err != nil {
				return err
			}
		}
		scanErr := tx.QueryRow(ctx, `
			UPDATE outbox AS queued
			   SET secret_sync_receiver_effect_state = 'effect_possible',
			       secret_sync_receiver_io_starts = queued.secret_sync_receiver_io_starts + 1
			  FROM secret_sync_jobs AS job
			 WHERE job.tenant_id = $1 AND job.tenant_epoch = $2
			   AND job.id = $3 AND job.outbox_id = $4
			   AND job.status = 'pending' AND job.target_order > 0
			   AND queued.tenant_id = job.tenant_id AND queued.id = job.outbox_id
			   AND queued.destination = 'secret.sync.' || job.target
			   AND queued.secret_sync_target_order = job.target_order
			   AND queued.status IN ('pending', 'processing')
			   AND queued.secret_sync_receiver_effect_state IN ('none', 'effect_possible')
			 RETURNING queued.secret_sync_receiver_io_starts`,
			tenantID, tenantEpoch, jobID, outboxID).Scan(&token)
		if scanErr == nil {
			proceed = true
			return nil
		}
		if !errors.Is(scanErr, pgx.ErrNoRows) {
			return scanErr
		}
		if authority.JobStatus != SecretSyncJobPending ||
			authority.EffectState == SecretSyncReceiverFailureAuthorized {
			return nil
		}
		return fmt.Errorf("%w: secret-sync receiver authority cannot start I/O", ErrIdempotencyConflict)
	})
	return token, proceed, err
}

// AuthorizeSecretSyncPreIOFailure records that no worker generation has ever
// crossed the receiver boundary. The caller must hold the terminal-choice lock;
// false means an earlier or concurrent generation made the current typed
// DefiniteNoEffect proof command-locally insufficient.
func (s *Store) AuthorizeSecretSyncPreIOFailure(
	ctx context.Context,
	tenantID, jobID string,
	outboxID int64,
	failureDetail string,
	failureAttempts int,
) (authorized bool, err error) {
	if tenantID == "" || jobID == "" || outboxID <= 0 || failureDetail == "" || failureAttempts < 1 {
		return false, errors.New("store: authorize secret-sync pre-I/O failure is incomplete")
	}
	err = s.WithTenantProjection(ctx, tenantID, func(tx pgx.Tx) error {
		tag, execErr := tx.Exec(ctx, `
			UPDATE outbox AS queued
			   SET secret_sync_receiver_effect_state = 'failure_authorized',
			       secret_sync_failure_detail = $4,
			       secret_sync_failure_attempts = $5
			  FROM secret_sync_jobs AS job
			 WHERE job.tenant_id = $1 AND job.id = $2 AND job.outbox_id = $3
			   AND job.status = 'pending' AND job.target_order > 0
			   AND queued.tenant_id = job.tenant_id AND queued.id = job.outbox_id
			   AND queued.destination = 'secret.sync.' || job.target
			   AND queued.secret_sync_target_order = job.target_order
			   AND queued.status IN ('pending', 'processing')
			   AND queued.secret_sync_receiver_effect_state = 'none'
			   AND queued.secret_sync_receiver_io_starts = 0`, tenantID, jobID, outboxID, failureDetail, failureAttempts)
		if execErr != nil {
			return execErr
		}
		if tag.RowsAffected() == 1 {
			authorized = true
			return nil
		}
		var authority SecretSyncReceiverAuthority
		if err := loadSecretSyncReceiverAuthorityTx(ctx, tx, tenantID, jobID, outboxID, &authority); err != nil {
			return err
		}
		switch {
		case authority.JobStatus != SecretSyncJobPending:
			return nil
		case authority.EffectState == SecretSyncReceiverFailureAuthorized:
			if authority.FailureDetail != failureDetail || authority.FailureAttempts != failureAttempts {
				return fmt.Errorf("%w: secret-sync failure authority detail differs", ErrIdempotencyConflict)
			}
			authorized = true
			return nil
		case authority.EffectState == SecretSyncReceiverEffectPossible:
			return nil
		default:
			return fmt.Errorf("%w: secret-sync pre-I/O authority differs", ErrIdempotencyConflict)
		}
	})
	return authorized, err
}

// AuthorizeSecretSyncOnlyStartedNoEffect converts effect_possible to terminal
// failure authority only when this exact worker owns the first and still-only
// receiver-start token. It is reserved for a typed target result that guarantees
// no network request was made (currently the enforced air-gap sentinel).
func (s *Store) AuthorizeSecretSyncOnlyStartedNoEffect(
	ctx context.Context,
	tenantID, jobID string,
	outboxID, token int64,
	failureDetail string,
	failureAttempts int,
) (authorized bool, err error) {
	if tenantID == "" || jobID == "" || outboxID <= 0 || token != 1 || failureDetail == "" || failureAttempts < 1 {
		return false, nil
	}
	err = s.WithTenantProjection(ctx, tenantID, func(tx pgx.Tx) error {
		tag, execErr := tx.Exec(ctx, `
			UPDATE outbox AS queued
			   SET secret_sync_receiver_effect_state = 'failure_authorized',
			       secret_sync_failure_detail = $5,
			       secret_sync_failure_attempts = $6
			  FROM secret_sync_jobs AS job
			 WHERE job.tenant_id = $1 AND job.id = $2 AND job.outbox_id = $3
			   AND job.status = 'pending' AND job.target_order > 0
			   AND queued.tenant_id = job.tenant_id AND queued.id = job.outbox_id
			   AND queued.destination = 'secret.sync.' || job.target
			   AND queued.secret_sync_target_order = job.target_order
			   AND queued.status IN ('pending', 'processing')
			   AND queued.secret_sync_receiver_effect_state = 'effect_possible'
			   AND queued.secret_sync_receiver_io_starts = $4`,
			tenantID, jobID, outboxID, token, failureDetail, failureAttempts)
		if execErr != nil {
			return execErr
		}
		authorized = tag.RowsAffected() == 1
		if authorized {
			return nil
		}
		var authority SecretSyncReceiverAuthority
		if err := loadSecretSyncReceiverAuthorityTx(ctx, tx, tenantID, jobID, outboxID, &authority); err != nil {
			return err
		}
		if authority.JobStatus != SecretSyncJobPending || authority.EffectState == SecretSyncReceiverEffectPossible {
			return nil
		}
		if authority.EffectState == SecretSyncReceiverFailureAuthorized {
			if authority.FailureDetail != failureDetail || authority.FailureAttempts != failureAttempts {
				return fmt.Errorf("%w: secret-sync failure authority detail differs", ErrIdempotencyConflict)
			}
			authorized = true
			return nil
		}
		return fmt.Errorf("%w: secret-sync only-started no-effect authority differs", ErrIdempotencyConflict)
	})
	return authorized, err
}

func loadSecretSyncReceiverAuthorityTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, jobID string,
	outboxID int64,
	authority *SecretSyncReceiverAuthority,
) error {
	err := scanSecretSyncReceiverAuthority(tx.QueryRow(ctx, `
		SELECT queued.id, job.status, queued.status, queued.attempts,
		       queued.secret_sync_receiver_effect_state,
		       queued.secret_sync_receiver_io_starts,
		       queued.secret_sync_failure_detail,
		       queued.secret_sync_failure_attempts
		  FROM secret_sync_jobs AS job
		  JOIN outbox AS queued
		    ON queued.tenant_id = job.tenant_id
		   AND queued.id = job.outbox_id
		   AND queued.destination = 'secret.sync.' || job.target
		   AND queued.secret_sync_target_order = job.target_order
		 WHERE job.tenant_id = $1 AND job.id = $2 AND job.outbox_id = $3
		 FOR UPDATE OF job, queued`, tenantID, jobID, outboxID), authority)
	return err
}

func scanSecretSyncReceiverAuthority(row rowScanner, authority *SecretSyncReceiverAuthority) error {
	return row.Scan(
		&authority.OutboxID, &authority.JobStatus, &authority.OutboxStatus, &authority.OutboxAttempts,
		&authority.EffectState, &authority.ReceiverIOStarts, &authority.FailureDetail,
		&authority.FailureAttempts,
	)
}

// ResolveSecretSyncTenantEpochTx validates a v2 explicit epoch, or maps a legacy
// v1 event to the current registration only when its global sequence is not from
// an older registration. The row locks serialize projection with offboarding.
func (s *Store) ResolveSecretSyncTenantEpochTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, eventEpoch string,
	eventSequence int64,
) (string, error) {
	if tenantID == "" || eventSequence <= 0 {
		return "", ErrApplicationSecretTenantEpochMismatch
	}
	if eventEpoch != "" {
		if err := s.ValidateApplicationSecretTenantEpochTx(ctx, tx, tenantID, eventEpoch); err != nil {
			return "", err
		}
		return eventEpoch, nil
	}
	if err := lockLiveTenantRegistrationTx(ctx, tx, tenantID); err != nil {
		return "", err
	}
	var registrationSequence int64
	var currentEpoch string
	err := tx.QueryRow(ctx, `
		SELECT tenant.event_seq, epoch.epoch_id::text
		  FROM tenants AS tenant
		  JOIN application_secret_tenant_epochs AS epoch
		    ON epoch.tenant_id = tenant.tenant_id
		 WHERE tenant.tenant_id = $1
		 FOR KEY SHARE OF epoch`, tenantID).Scan(&registrationSequence, &currentEpoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrApplicationSecretTenantEpochMismatch
	}
	if err != nil {
		return "", err
	}
	if eventSequence < registrationSequence || currentEpoch == "" {
		return "", ErrApplicationSecretTenantEpochMismatch
	}
	return currentEpoch, nil
}

// ResolveSecretSyncQueuedTenantEpochTx is the one secret-sync event mapping
// allowed to create registration authority. A queued event is the lifecycle
// root, so a fresh event-only recovery target may not have the independent
// application-secret epoch row yet. A current event restores its exact named
// epoch; a legacy event creates one. The exact tenant registration row stays
// locked while its retained sequence is checked and the epoch is created.
// Delivered/failed events continue through ResolveSecretSyncTenantEpochTx and
// can never synthesize authority.
func (s *Store) ResolveSecretSyncQueuedTenantEpochTx(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, eventEpoch string,
	eventSequence int64,
) (string, error) {
	if tenantID == "" || eventSequence <= 0 {
		return "", ErrApplicationSecretTenantEpochMismatch
	}
	if eventEpoch != "" {
		parsed, err := uuid.Parse(eventEpoch)
		if err != nil || parsed.String() != eventEpoch {
			return "", ErrApplicationSecretTenantEpochMismatch
		}
	}
	registration, err := s.LockLiveTenantRegistrationSnapshotTx(ctx, tx, tenantID)
	if err != nil {
		return "", err
	}
	if uint64(eventSequence) < registration.EventSeq {
		return "", ErrApplicationSecretTenantEpochMismatch
	}
	insertSQL := `
		INSERT INTO application_secret_tenant_epochs (tenant_id, epoch_id)
		VALUES ($1, gen_random_uuid())
		ON CONFLICT (tenant_id) DO NOTHING`
	insertArgs := []any{tenantID}
	if eventEpoch != "" {
		insertSQL = `
			INSERT INTO application_secret_tenant_epochs (tenant_id, epoch_id)
			VALUES ($1, $2)
			ON CONFLICT (tenant_id) DO NOTHING`
		insertArgs = append(insertArgs, eventEpoch)
	}
	if _, err := tx.Exec(ctx, insertSQL, insertArgs...); err != nil {
		return "", fmt.Errorf("store: create secret-sync queued tenant epoch: %w", err)
	}
	var currentEpoch string
	if err := tx.QueryRow(ctx, `
		SELECT epoch_id::text
		  FROM application_secret_tenant_epochs
		 WHERE tenant_id = $1
		 FOR KEY SHARE`, tenantID).Scan(&currentEpoch); err != nil {
		return "", err
	}
	if currentEpoch == "" {
		return "", ErrApplicationSecretTenantEpochMismatch
	}
	if eventEpoch != "" && currentEpoch != eventEpoch {
		return "", ErrApplicationSecretTenantEpochMismatch
	}
	return currentEpoch, nil
}

// SecretSyncOutboxIdempotencyKey is the one receiver command identity shared by
// event producers, projections, queue adapters, and completion/recovery code.
// The stable job ID already binds the tenant and originating command; target is
// included so two configured receivers can never share an outbox namespace.
func SecretSyncOutboxIdempotencyKey(target, jobID string) string {
	return "secret.sync." + target + ":" + jobID
}

// SecretSyncHasOlderNonterminal reports whether an immutable older target order
// command for the same tenant target can still run. The entire target is the
// causal unit because provider adapters may normalize distinct raw key spellings
// to the same external object. next_attempt_at is deliberately ignored: a
// backoff is not permission for a newer value to pass and later overwrite it.
func (s *Store) SecretSyncHasOlderNonterminal(ctx context.Context, tenantID, target string, outboxID int64) (bool, error) {
	if tenantID == "" || target == "" || outboxID <= 0 {
		return false, fmt.Errorf("store: secret-sync predecessor check is incomplete")
	}
	var targetOrder int64
	var blocked bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT current_outbox.secret_sync_target_order,
			        EXISTS (
			     SELECT 1
			       FROM outbox older_outbox
			       LEFT JOIN secret_sync_jobs older_job
			         ON older_job.tenant_id = older_outbox.tenant_id
			        AND older_job.outbox_id = older_outbox.id
			        AND older_job.target_order = older_outbox.secret_sync_target_order
			        AND older_outbox.destination = 'secret.sync.' || older_job.target
			      WHERE older_outbox.tenant_id = current_outbox.tenant_id
			        AND older_outbox.destination = current_outbox.destination
			        AND older_outbox.secret_sync_target_order < current_outbox.secret_sync_target_order
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
			 )
			  FROM outbox current_outbox
			 WHERE current_outbox.tenant_id = $1
			   AND current_outbox.destination = 'secret.sync.' || $2
			   AND current_outbox.id = $3`,
			tenantID, target, outboxID).Scan(&targetOrder, &blocked)
	})
	if err == nil && targetOrder <= 0 {
		return false, fmt.Errorf("store: secret-sync target order is invalid")
	}
	return blocked, err
}
