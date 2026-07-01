package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// SecretRotationSchedule is a tenant-owned cadence for rollback-safe static
// credential rotation. It stores references and run metadata only, never generated
// credential values.
type SecretRotationSchedule struct {
	ID              string
	TenantID        string
	Name            string
	Provider        string
	Key             string
	OldRef          string
	IntervalSeconds int
	Enabled         bool
	NextRunAt       time.Time
	LastRunID       *string
	LastRunAt       *time.Time
	LastRunStatus   string
	LastNewRef      string
	LastError       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// SecretRotationScheduleRun is the projected result of one scheduled rotation
// tick. Status is metadata such as completed, rolled_back, or failed.
type SecretRotationScheduleRun struct {
	TenantID   string
	ScheduleID string
	RunID      string
	Status     string
	NewRef     string
	Error      string
	RanAt      time.Time
}

// ApplySecretRotationScheduleUpsertedTx projects a
// secret.rotation_schedule.upserted event.
func (s *Store) ApplySecretRotationScheduleUpsertedTx(ctx context.Context, tx pgx.Tx, sched SecretRotationSchedule) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO secret_rotation_schedules
		        (id, tenant_id, name, provider, secret_key, old_ref, interval_seconds,
		         enabled, next_run_at, created_at, updated_at)
		      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (tenant_id, id) DO UPDATE
		      SET name = EXCLUDED.name,
		          provider = EXCLUDED.provider,
		          secret_key = EXCLUDED.secret_key,
		          old_ref = EXCLUDED.old_ref,
		          interval_seconds = EXCLUDED.interval_seconds,
		          enabled = EXCLUDED.enabled,
		          next_run_at = EXCLUDED.next_run_at,
		          updated_at = EXCLUDED.updated_at`,
		sched.ID, sched.TenantID, sched.Name, sched.Provider, sched.Key, sched.OldRef,
		sched.IntervalSeconds, sched.Enabled, sched.NextRunAt, sched.CreatedAt, sched.UpdatedAt)
	return err
}

// ApplySecretRotationScheduleRunTx projects a scheduled rotation outcome and
// advances the next due time. A completed run promotes the successor reference so
// the next rotation retires the version that just became old.
func (s *Store) ApplySecretRotationScheduleRunTx(ctx context.Context, tx pgx.Tx, run SecretRotationScheduleRun) error {
	tag, err := tx.Exec(ctx,
		`UPDATE secret_rotation_schedules
		    SET old_ref = CASE
		            WHEN $4 = 'completed' AND $5 <> '' THEN $5
		            ELSE old_ref
		        END,
		        next_run_at = $7::timestamptz + (interval_seconds * interval '1 second'),
		        last_run_id = $3::uuid,
		        last_run_at = $7::timestamptz,
		        last_run_status = $4,
		        last_new_ref = $5,
		        last_error = $6,
		        updated_at = $7::timestamptz
		  WHERE tenant_id = $1 AND id = $2`,
		run.TenantID, run.ScheduleID, run.RunID, run.Status, run.NewRef, run.Error, run.RanAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ListSecretRotationSchedulesPage lists tenant schedules by id keyset.
func (s *Store) ListSecretRotationSchedulesPage(ctx context.Context, tenantID, afterID string, limit int) ([]SecretRotationSchedule, error) {
	var out []SecretRotationSchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, provider, secret_key, old_ref, interval_seconds,
			        enabled, next_run_at, last_run_id::text, last_run_at, last_run_status,
			        last_new_ref, last_error, created_at, updated_at
			   FROM secret_rotation_schedules
			  WHERE tenant_id = $1 AND id > $2
			  ORDER BY id LIMIT $3`, tenantID, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sched SecretRotationSchedule
			if err := scanSecretRotationSchedule(rows, &sched); err != nil {
				return err
			}
			out = append(out, sched)
		}
		return rows.Err()
	})
	return out, err
}

// ListDueSecretRotationSchedules loads enabled tenant schedules due no later than
// now, oldest due time first.
func (s *Store) ListDueSecretRotationSchedules(ctx context.Context, tenantID string, now time.Time, limit int) ([]SecretRotationSchedule, error) {
	var out []SecretRotationSchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id::text, tenant_id::text, name, provider, secret_key, old_ref, interval_seconds,
			        enabled, next_run_at, last_run_id::text, last_run_at, last_run_status,
			        last_new_ref, last_error, created_at, updated_at
			   FROM secret_rotation_schedules
			  WHERE tenant_id = $1 AND enabled AND next_run_at <= $2
			  ORDER BY next_run_at, id LIMIT $3`, tenantID, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sched SecretRotationSchedule
			if err := scanSecretRotationSchedule(rows, &sched); err != nil {
				return err
			}
			out = append(out, sched)
		}
		return rows.Err()
	})
	return out, err
}

// GetSecretRotationSchedule loads one tenant-scoped rotation schedule.
func (s *Store) GetSecretRotationSchedule(ctx context.Context, tenantID, id string) (SecretRotationSchedule, error) {
	var out SecretRotationSchedule
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanSecretRotationSchedule(tx.QueryRow(ctx,
			`SELECT id::text, tenant_id::text, name, provider, secret_key, old_ref, interval_seconds,
			        enabled, next_run_at, last_run_id::text, last_run_at, last_run_status,
			        last_new_ref, last_error, created_at, updated_at
			   FROM secret_rotation_schedules
			  WHERE tenant_id = $1 AND id = $2`, tenantID, id), &out)
	})
	return out, err
}

func scanSecretRotationSchedule(row rowScanner, sched *SecretRotationSchedule) error {
	return row.Scan(&sched.ID, &sched.TenantID, &sched.Name, &sched.Provider, &sched.Key,
		&sched.OldRef, &sched.IntervalSeconds, &sched.Enabled, &sched.NextRunAt,
		&sched.LastRunID, &sched.LastRunAt, &sched.LastRunStatus, &sched.LastNewRef,
		&sched.LastError, &sched.CreatedAt, &sched.UpdatedAt)
}
