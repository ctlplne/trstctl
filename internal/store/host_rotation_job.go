// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// HostRotationJob retains the exact retired claim needed to complete a host
// rotation. Pending/released attempts deliberately have no terminal timestamp.
type HostRotationJob struct {
	ID                                  int64
	Destination, IdempotencyKey, Status string
	Payload                             []byte
	Attempt                             int
	CompletedAt                         *time.Time
}

func (s *Store) GetHostRotationJob(ctx context.Context, tenantID string, jobID int64) (HostRotationJob, error) {
	var job HostRotationJob
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, destination, idempotency_key, status, payload,
		    claim_attempts, claim_completed_at FROM outbox WHERE tenant_id = $1 AND id = $2`, tenantID, jobID).
			Scan(&job.ID, &job.Destination, &job.IdempotencyKey, &job.Status, &job.Payload, &job.Attempt, &job.CompletedAt)
	})
	return job, err
}

// RotationRunHostJob returns only the child command explicitly bound to this
// run. Absence is valid for control-plane and legacy runs; malformed bindings
// are errors. The returned payload stays internal and must not enter the API.
func (s *Store) RotationRunHostJob(ctx context.Context, tenantID string, run RotationRun) (*HostRotationJob, error) {
	if run.TenantID != tenantID {
		return nil, errors.New("host rotation run tenant mismatch")
	}
	var job HostRotationJob
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id, destination, idempotency_key, status, payload,
			claim_attempts, claim_completed_at FROM outbox
			WHERE tenant_id=$1 AND destination='endpoint.renew' AND idempotency_key=$2`,
			tenantID, "host-renew:renew:"+run.IdempotencyKey).
			Scan(&job.ID, &job.Destination, &job.IdempotencyKey, &job.Status, &job.Payload, &job.Attempt, &job.CompletedAt)
		if err != nil {
			return err
		}
		var intent struct {
			IdentityID               string `json:"identity_id"`
			RotationRunID            string `json:"rotation_run_id"`
			PredecessorCertificateID string `json:"predecessor_certificate_id"`
		}
		if json.Unmarshal(job.Payload, &intent) != nil || intent.RotationRunID != run.ID || intent.IdentityID != run.IdentityID {
			return errors.New("host rotation job differs from its run binding")
		}
		var bound bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM certificates
			WHERE tenant_id=$1 AND id=$2 AND fingerprint=$3)`,
			tenantID, intent.PredecessorCertificateID, run.PredecessorFingerprint).Scan(&bound); err != nil {
			return err
		}
		if !bound {
			return errors.New("host rotation job differs from its predecessor")
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &job, nil
}

// PendingHostRotationResults returns a bounded page of retired host jobs whose
// run still lacks terminal evidence. Payloads remain behind the tenant's RLS.
func (s *Store) PendingHostRotationResults(ctx context.Context, tenantID string, afterID int64) ([]int64, error) {
	var ids []int64
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT job.id FROM outbox AS job
		    JOIN lifecycle_rotation_runs AS run ON run.tenant_id = job.tenant_id
		      AND job.idempotency_key = 'host-renew:renew:' || run.idempotency_key
		    WHERE job.tenant_id = $1 AND job.id > $2 AND job.destination = 'endpoint.renew'
		      AND job.status IN ('delivered', 'failed') AND job.claim_completed_at IS NOT NULL
		      AND run.status = 'running' ORDER BY job.id LIMIT 1`, tenantID, afterID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	return ids, err
}

// NextHostRotationRecoveryTenant enumerates only the public tenant registry.
// Job payload and lifecycle reads still require each tenant's RLS transaction.
func (s *Store) NextHostRotationRecoveryTenant(ctx context.Context, after string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		//trstctl:system-query — cross-tenant system recovery reads at most one public-registry tenant_id per cursor step; job payloads and mutations remain inside the owning tenant's RLS context.
		`SELECT tenant_id::text FROM tenants WHERE tenant_id > COALESCE(NULLIF($1,'')::uuid,'00000000-0000-0000-0000-000000000000'::uuid) ORDER BY tenant_id LIMIT 1`, after).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// HostRotationLookup is a disposable source-log index, never outcome authority.
// Each candidate is reloaded from its retained envelope before it can complete a run.
type HostRotationLookup struct {
	Generation                               string
	Next, Through, Delivery, Custody, Result int64
}

func (s *Store) HostRotationLookup(ctx context.Context, tenantID string, jobID int64, attempt int) (HostRotationLookup, error) {
	var lookup HostRotationLookup
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT host_rotation_scan_generation,host_rotation_scan_next,host_rotation_scan_through,
   host_rotation_delivery_sequence,host_rotation_custody_sequence,host_rotation_result_sequence
   FROM outbox WHERE tenant_id=$1 AND id=$2 AND claim_attempts=$3 AND claim_completed_at IS NOT NULL`, tenantID, jobID, attempt).
			Scan(&lookup.Generation, &lookup.Next, &lookup.Through, &lookup.Delivery, &lookup.Custody, &lookup.Result)
	})
	return lookup, err
}

func (s *Store) SaveHostRotationLookup(ctx context.Context, tenantID string, jobID int64, attempt int, lookup HostRotationLookup) error {
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE outbox SET host_rotation_scan_generation=$4,host_rotation_scan_next=$5,
   host_rotation_delivery_sequence=$6,host_rotation_custody_sequence=$7,host_rotation_result_sequence=$8,host_rotation_scan_through=$9
   WHERE tenant_id=$1 AND id=$2 AND claim_attempts=$3 AND claim_completed_at IS NOT NULL`,
			tenantID, jobID, attempt, lookup.Generation, lookup.Next, lookup.Delivery, lookup.Custody, lookup.Result, lookup.Through)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("host rotation lookup lost its retired claim")
		}
		return nil
	})
}

// WithHostRotationResultLock serializes result lookup/publish for one retired
// job across replicas. A busy job rejects fast; unrelated jobs do not wait on it.
func (s *Store) WithHostRotationResultLock(ctx context.Context, tenantID string, jobID int64, fn func(context.Context) error) error {
	conn, err := s.lockSessionPool(ctx).Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	key := fmt.Sprintf("host-rotation-result:%s:%d", tenantID, jobID)
	var held bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, key).Scan(&held); err != nil {
		return err
	}
	if !held {
		return errors.New("host rotation result is already being reconciled")
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := conn.Exec(unlockCtx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, key); err != nil {
			_ = conn.Conn().Close(unlockCtx)
		}
	}()
	return fn(ctx)
}
