// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
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

// WithProjectionLock runs fn while holding the projection advisory lock on a
// dedicated session connection (RESIL-004), so concurrent boot catch-ups across
// replicas serialize rather than racing into the read model. The lock is released
// when fn returns (even on error or a cancelled ctx). It is a system operation on
// the pool, like the migration lock.
func (s *Store) WithProjectionLock(ctx context.Context, fn func(context.Context) error) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("store: acquire projection-lock connection: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", ProjectionAdvisoryLockKey); err != nil {
		return fmt.Errorf("store: acquire projection lock: %w", err)
	}
	defer func() {
		// Release on a fresh context so the lock drops even if ctx is done.
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", ProjectionAdvisoryLockKey)
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
	err := s.pool.QueryRow(ctx,
		`SELECT applied_seq FROM projection_checkpoint WHERE id = 1`).Scan(&seq)
	if err != nil {
		return 0, fmt.Errorf("store: read projection checkpoint: %w", err)
	}
	if seq < 0 {
		seq = 0
	}
	return uint64(seq), nil
}

// AdvanceProjectionCheckpoint moves the read model's high-water mark forward to
// seq (SPINE-007). It only ever advances — a concurrent or stale caller writing a
// lower value is ignored (GREATEST), so two catch-up paths cannot rewind the
// watermark and cause a re-replay. It is a system (RLS-bypassing) write of the
// single-row table.
func (s *Store) AdvanceProjectionCheckpoint(ctx context.Context, seq uint64) error {
	// System table (no tenant_id by design): advance the single global watermark
	// row on the pool. GREATEST makes the advance monotonic and idempotent.
	_, err := s.pool.Exec(ctx,
		`UPDATE projection_checkpoint
		    SET applied_seq = GREATEST(applied_seq, $1), updated_at = now()
		  WHERE id = 1`, int64(seq))
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
		`UPDATE projection_checkpoint SET applied_seq = $1, updated_at = now() WHERE id = 1`, int64(seq))
	if err != nil {
		return fmt.Errorf("store: set projection checkpoint: %w", err)
	}
	return nil
}

// ResetProjectionCheckpointTx sets the read model's high-water mark back to 0 on
// the caller's transaction (SPINE-007). A full Rebuild (disaster recovery /
// migration) re-derives the entire read model from sequence 0, so it must clear
// the watermark in the SAME transaction as the truncate+replay — otherwise a
// crash could leave a non-zero watermark over an emptied read model and skip a
// re-replay. It runs on the rebuild's transaction (the owner role); it is a
// system write of the single-row table.
func (s *Store) ResetProjectionCheckpointTx(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx,
		`UPDATE projection_checkpoint SET applied_seq = 0, updated_at = now() WHERE id = 1`)
	if err != nil {
		return fmt.Errorf("store: reset projection checkpoint: %w", err)
	}
	return nil
}
