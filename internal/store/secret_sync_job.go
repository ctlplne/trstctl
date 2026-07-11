// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
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

// SecretSyncJob is delivery evidence for one version of one secret sent to one
// configured target. ValueDigest may be used for drift comparison, but the secret
// value itself is never persisted here; the encrypted outbox payload remains the
// delivery authority (AN-6, AN-8).
type SecretSyncJob struct {
	ID             string
	TenantID       string
	SecretName     string
	SecretVersion  int64
	Target         string
	RemoteKey      string
	ValueDigest    string
	Status         SecretSyncJobStatus
	OutboxID       int64
	Attempts       int
	RemoteVersion  string
	LastError      string
	IdempotencyKey string
	RequestBinding string
	RequestedAt    time.Time
	UpdatedAt      time.Time
	DeliveredAt    *time.Time
}

// ApplySecretSyncJobQueuedTx projects a secret.sync.queued event. The caller
// enqueues OutboxID in the same transaction as this projection (AN-6). A duplicate
// event is a no-op, so it cannot regress later delivery evidence back to pending.
func (s *Store) ApplySecretSyncJobQueuedTx(ctx context.Context, tx pgx.Tx, job SecretSyncJob) error {
	updatedAt := job.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = job.RequestedAt
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO secret_sync_jobs
		        (tenant_id, id, secret_name, secret_version, target, remote_key,
		         value_digest, status, outbox_id, attempts, remote_version,
		         last_error, idempotency_key, request_binding, requested_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, 0, '', '', $9, $10, $11, $12)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		    SET id = secret_sync_jobs.id
		  WHERE secret_sync_jobs.secret_name = EXCLUDED.secret_name
		    AND secret_sync_jobs.secret_version = EXCLUDED.secret_version
		    AND secret_sync_jobs.target = EXCLUDED.target
		    AND secret_sync_jobs.remote_key = EXCLUDED.remote_key
		    AND secret_sync_jobs.value_digest = EXCLUDED.value_digest
		    AND secret_sync_jobs.outbox_id = EXCLUDED.outbox_id
		    AND secret_sync_jobs.idempotency_key = EXCLUDED.idempotency_key
		    AND secret_sync_jobs.request_binding = EXCLUDED.request_binding`,
		job.TenantID, job.ID, job.SecretName, job.SecretVersion, job.Target,
		job.RemoteKey, job.ValueDigest, job.OutboxID, job.IdempotencyKey, job.RequestBinding,
		job.RequestedAt, updatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: secret-sync job %s", ErrIdempotencyConflict, job.ID)
	}
	return nil
}

// ApplySecretSyncJobDeliveredTx projects a successful idempotent target write.
// RemoteVersion is the target's non-secret version/etag/revision evidence when it
// exposes one.
func (s *Store) ApplySecretSyncJobDeliveredTx(ctx context.Context, tx pgx.Tx, tenantID, jobID string, attempts int, remoteVersion string, deliveredAt time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE secret_sync_jobs
		    SET status = 'delivered', attempts = GREATEST(attempts, $3),
		        remote_version = $4, last_error = '', delivered_at = $5,
		        updated_at = GREATEST(updated_at, $5)
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, jobID, attempts, remoteVersion, deliveredAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ApplySecretSyncJobFailedTx projects a terminal outbox failure. A stale failure
// replayed after a success leaves delivered evidence untouched.
func (s *Store) ApplySecretSyncJobFailedTx(ctx context.Context, tx pgx.Tx, tenantID, jobID string, attempts int, lastError string, failedAt time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE secret_sync_jobs
		    SET status = CASE WHEN status = 'delivered' THEN status ELSE 'failed' END,
		        attempts = GREATEST(attempts, $3),
		        last_error = CASE WHEN status = 'delivered' THEN last_error ELSE $4 END,
		        updated_at = GREATEST(updated_at, $5)
		  WHERE tenant_id = $1 AND id = $2`,
		tenantID, jobID, attempts, lastError, failedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// GetSecretSyncJob returns one sync job in its tenant's RLS context.
func (s *Store) GetSecretSyncJob(ctx context.Context, tenantID, jobID string) (SecretSyncJob, error) {
	var job SecretSyncJob
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanSecretSyncJob(tx.QueryRow(ctx,
			`SELECT id, tenant_id::text, secret_name, secret_version, target,
			        remote_key, value_digest, status, outbox_id, attempts,
			        remote_version, last_error, idempotency_key, request_binding, requested_at,
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
			`SELECT id, tenant_id::text, secret_name, secret_version, target,
			        remote_key, value_digest, status, outbox_id, attempts,
			        remote_version, last_error, idempotency_key, request_binding, requested_at,
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
			`SELECT id, tenant_id::text, secret_name, secret_version, target,
			        remote_key, value_digest, status, outbox_id, attempts,
			        remote_version, last_error, idempotency_key, request_binding, requested_at,
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
		&job.ID, &job.TenantID, &job.SecretName, &job.SecretVersion, &job.Target,
		&job.RemoteKey, &job.ValueDigest, &job.Status, &job.OutboxID, &job.Attempts,
		&job.RemoteVersion, &job.LastError, &job.IdempotencyKey, &job.RequestBinding, &job.RequestedAt,
		&job.UpdatedAt, &job.DeliveredAt,
	)
}

var secretSyncJobNamespace = uuid.MustParse("dc064ff8-bcd7-5ac1-a310-65cb5ccf3cc1")

// DurableSecretSyncJobID is the stable tenant + raw Idempotency-Key identity
// shared by the API and event producer. Looking it up avoids opening the current
// source secret on a replay after the short-lived response recorder is collected.
func DurableSecretSyncJobID(tenantID, idempotencyKey string) string {
	return "sync-" + uuid.NewSHA1(secretSyncJobNamespace, []byte(tenantID+"\x00"+idempotencyKey)).String()
}
