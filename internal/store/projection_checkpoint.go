// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ProjectionAdvisoryLockKey is the fixed PostgreSQL advisory-lock key every
// instance takes for the duration of a boot projection catch-up (RESIL-004).
// Because all replicas of one deployment share the database and the key, only one
// catch-up runs at a time: a second replica booting concurrently BLOCKS on this
// lock until the first finishes, then resumes from the advanced checkpoint and has
// little or nothing left to apply. This serializes the otherwise-uncoordinated
// per-replica catch-up into the shared read-model tables, so a non-idempotent
// apply ordering cannot interleave between two projectors. The value spells ASCII
// "ctlprj"; operators can see it held in pg_locks (locktype = 'advisory'). It is a
// DIFFERENT key from the migration lock so a catch-up and a migration do not block
// each other.
const ProjectionAdvisoryLockKey int64 = 0x63746C70726A // "ctlprj"

// maxProjectionTailErrorBytes keeps one poison diagnostic small enough for
// readiness and operator readout paths. The raw event payload is never stored;
// this is only the bounded error returned by the projector.
const maxProjectionTailErrorBytes = 2048

// ProjectionTailHealth is the persisted, tenant-neutral state of the ordered
// projection cursor. FailedSequence == 0 means there is no unresolved poison.
// LastError is bounded operational metadata that can still contain tenant or
// dependency detail. Callers must treat it as protected data and choose a safer
// summary for unauthenticated probes.
type ProjectionTailHealth struct {
	AppliedSequence uint64
	FailedSequence  uint64
	LastError       string
	FailedAt        *time.Time
	UpdatedAt       time.Time
}

// WithProjectionLock runs fn while holding the projection advisory lock on a
// dedicated session connection (RESIL-004), so concurrent boot catch-ups across
// replicas serialize rather than racing into the read model. The lock is released
// when fn returns (even on error or a canceled ctx). It is a system operation on
// the pool, like the migration lock.
func (s *Store) WithProjectionLock(ctx context.Context, fn func(context.Context) error) error {
	// The lock-holding session comes from the lock pool: a command parked on
	// the advisory lock must not hold a request-pool connection, because the
	// holder's nested transactions need that pool and a burst of waiters starved
	// it into the acquire window (DP2-061). The callback still runs its own
	// transactions on the pool ctx is entitled to.
	var conn *pgxpool.Conn
	if fence, _ := ctx.Value(identityIssuanceFenceKey{}).(*identityIssuanceFence); fence != nil && fence.store == s {
		if !fence.active.Load() {
			return errors.New("store: identity issuance fence has ended")
		}
		conn = fence.conn
	} else {
		borrowed, release, err := s.borrowTenantServiceSession(ctx)
		if err != nil {
			return err
		}
		defer release()
		conn = borrowed
		if conn == nil {
			conn, err = s.lockSessionPool(ctx).Acquire(ctx)
			if err != nil {
				return fmt.Errorf("store: acquire projection-lock connection: %w", err)
			}
			defer conn.Release()
		}
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", ProjectionAdvisoryLockKey); err != nil {
		return fmt.Errorf("store: acquire projection lock: %w", err)
	}
	defer func() {
		// Release on a fresh context so the lock drops even if ctx is done.
		unlockCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", ProjectionAdvisoryLockKey); err != nil {
			_ = conn.Conn().Close(unlockCtx)
		}
	}()
	return fn(ctx)
}

// ProjectionCheckpoint reads the relational read model's high-water mark: the
// highest event-stream sequence that has been applied (SPINE-007). It is a system
// (cross-tenant, RLS-bypassing) read of the single-row projection_checkpoint
// table — the watermark is one global number for the whole deployment, since the
// event-stream sequence is global and monotonic. A fresh database returns 0 (no
// events applied yet), which drives a full catch-up on first boot.
func (s *Store) ProjectionCheckpoint(ctx context.Context) (uint64, error) {
	var seq int64
	// projection_checkpoint is a system table (no tenant_id by design); it is read
	// on the pool, not under a tenant RLS context, like schema_migrations.
	err := s.poolFor(ctx).QueryRow(ctx,
		`SELECT applied_seq FROM projection_checkpoint WHERE id = 1`).Scan(&seq)
	if err != nil {
		return 0, fmt.Errorf("store: read projection checkpoint: %w", err)
	}
	if seq < 0 {
		seq = 0
	}
	return uint64(seq), nil
}

// ProjectionTailHealth reads the global projection checkpoint together with its
// unresolved failure marker. The event stream is globally ordered, so this is a
// system read with no tenant_id, just like ProjectionCheckpoint.
func (s *Store) ProjectionTailHealth(ctx context.Context) (ProjectionTailHealth, error) {
	var (
		health     ProjectionTailHealth
		appliedSeq int64
		failedSeq  *int64
		lastError  *string
		failedAt   *time.Time
	)
	err := s.poolFor(ctx).QueryRow(ctx,
		`SELECT applied_seq, failed_seq, last_error, failed_at, updated_at
		   FROM projection_checkpoint
		  WHERE id = 1`).Scan(&appliedSeq, &failedSeq, &lastError, &failedAt, &health.UpdatedAt)
	if err != nil {
		return ProjectionTailHealth{}, fmt.Errorf("store: read projection tail health: %w", err)
	}
	if appliedSeq > 0 {
		health.AppliedSequence = uint64(appliedSeq)
	}
	if failedSeq != nil && *failedSeq > 0 {
		health.FailedSequence = uint64(*failedSeq)
	}
	if lastError != nil {
		health.LastError = *lastError
	}
	health.FailedAt = failedAt
	return health, nil
}

// RecordProjectionTailFailure persists the earliest unresolved event sequence
// before TailWorker returns. A stale replica cannot paint a sequence at or below
// the already-applied checkpoint as failed, and a later failure cannot hide an
// earlier poison that still blocks the ordered stream.
func (s *Store) RecordProjectionTailFailure(ctx context.Context, seq uint64, cause error) error {
	if seq == 0 {
		return errors.New("store: projection tail failure sequence must be positive")
	}
	detail := sanitizeProjectionTailError(cause)
	_, err := s.poolFor(ctx).Exec(ctx,
		`UPDATE projection_checkpoint
		    SET failed_seq = $1, last_error = $2, failed_at = now(), updated_at = now()
		  WHERE id = 1
		    AND applied_seq < $1
		    AND (failed_seq IS NULL OR failed_seq >= $1)`,
		int64(seq), detail) // #nosec G115 -- event sequence fits the PostgreSQL bigint used by the event log (CWE-190)
	if err != nil {
		return fmt.Errorf("store: record projection tail failure at seq %d: %w", seq, err)
	}
	return nil
}

func sanitizeProjectionTailError(cause error) string {
	detail := "projection failed"
	if cause != nil {
		detail = strings.ToValidUTF8(cause.Error(), "�")
	}
	detail = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, detail)
	detail = strings.Join(strings.Fields(detail), " ")
	if detail == "" {
		detail = "projection failed"
	}
	if len(detail) <= maxProjectionTailErrorBytes {
		return detail
	}
	detail = detail[:maxProjectionTailErrorBytes]
	for !utf8.ValidString(detail) {
		detail = detail[:len(detail)-1]
	}
	return detail
}

// AdvanceProjectionCheckpoint moves the read model's high-water mark forward to
// seq (SPINE-007). It only ever advances — a concurrent or stale caller writing a
// lower value is ignored (GREATEST), so two catch-up paths cannot rewind the
// watermark and cause a re-replay. It is a system (RLS-bypassing) write of the
// single-row table.
func (s *Store) AdvanceProjectionCheckpoint(ctx context.Context, seq uint64) error {
	// System table (no tenant_id by design): advance the single global watermark
	// row on the pool. GREATEST makes the advance monotonic and idempotent.
	_, err := s.poolFor(ctx).Exec(ctx,
		`UPDATE projection_checkpoint
		    SET applied_seq = GREATEST(applied_seq, $1),
		        failed_seq = CASE
		            WHEN failed_seq <= GREATEST(applied_seq, $1) THEN NULL
		            ELSE failed_seq
		        END,
		        last_error = CASE
		            WHEN failed_seq <= GREATEST(applied_seq, $1) THEN NULL
		            ELSE last_error
		        END,
		        failed_at = CASE
		            WHEN failed_seq <= GREATEST(applied_seq, $1) THEN NULL
		            ELSE failed_at
		        END,
		        updated_at = now()
		  WHERE id = 1`, int64(seq)) // #nosec G115 -- event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190)
	if err != nil {
		return fmt.Errorf("store: advance projection checkpoint: %w", err)
	}
	return nil
}

// SetProjectionCheckpointTx sets the read model's high-water mark to an exact
// value on the caller's transaction (SPINE-007). After a full Rebuild re-derives
// the read model from sequence 0, it advances the watermark to the rebuilt head in
// the SAME transaction, so the post-rebuild boot resumes catch-up from there
// rather than re-replaying everything. It is a system write of the single-row
// table.
func (s *Store) SetProjectionCheckpointTx(ctx context.Context, tx pgx.Tx, seq uint64) error {
	_, err := tx.Exec(ctx,
		`UPDATE projection_checkpoint
		    SET applied_seq = $1,
		        failed_seq = CASE WHEN failed_seq <= $1 THEN NULL ELSE failed_seq END,
		        last_error = CASE WHEN failed_seq <= $1 THEN NULL ELSE last_error END,
		        failed_at = CASE WHEN failed_seq <= $1 THEN NULL ELSE failed_at END,
		        updated_at = now()
		  WHERE id = 1`, int64(seq)) // #nosec G115 -- event sequence/count fits int64 by construction; the column is a Postgres bigint (CWE-190)
	if err != nil {
		return fmt.Errorf("store: set projection checkpoint: %w", err)
	}
	return nil
}

// ResetProjectionCheckpointTx sets the read model's high-water mark back to 0 on
// the caller's transaction (SPINE-007). A full Rebuild (disaster recovery /
// migration) re-derives the entire read model from sequence 0, so it must clear
// the watermark and old failure marker in the SAME transaction as the
// truncate+replay — otherwise a crash could leave a non-zero watermark over an
// emptied read model and skip a re-replay. A failed rebuild rolls this reset back,
// so its poison remains visible. It runs on the rebuild's transaction (the owner
// role); it is a system write of the single-row table.
func (s *Store) ResetProjectionCheckpointTx(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx,
		`UPDATE projection_checkpoint
		    SET applied_seq = 0, failed_seq = NULL, last_error = NULL,
		        failed_at = NULL, updated_at = now()
		  WHERE id = 1`)
	if err != nil {
		return fmt.Errorf("store: reset projection checkpoint: %w", err)
	}
	return nil
}
