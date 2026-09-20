// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// TestProjectionTailHealthPersistsUntilCheckpointCoversFailure is the AUD-103
// storage contract. The projection cursor is global, so its failure marker is
// global too: it has no tenant_id, survives a process restart, and disappears in
// the SAME write that moves the cursor through the failed event.
func TestProjectionTailHealthPersistsUntilCheckpointCoversFailure(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	resetProjectionTailHealthFixture(t, s)

	if err := s.AdvanceProjectionCheckpoint(ctx, 3); err != nil {
		t.Fatalf("seed projection checkpoint: %v", err)
	}
	unsafeDetail := "  decoder\nrefused\x00" + strings.Repeat("x", 5000) + "  "
	if err := s.RecordProjectionTailFailure(ctx, 11, errors.New(unsafeDetail)); err != nil {
		t.Fatalf("RecordProjectionTailFailure: %v", err)
	}

	health, err := s.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatalf("ProjectionTailHealth: %v", err)
	}
	if health.AppliedSequence != 3 || health.FailedSequence != 11 {
		t.Fatalf("persisted health = %+v, want applied=3 failed=11", health)
	}
	if health.FailedAt == nil || health.UpdatedAt.IsZero() {
		t.Fatalf("failure timestamps were not persisted: %+v", health)
	}
	if health.LastError == "" || len(health.LastError) > 2048 {
		t.Fatalf("stored error length = %d, want 1..2048", len(health.LastError))
	}
	if strings.IndexFunc(health.LastError, unicode.IsControl) >= 0 {
		t.Fatalf("stored error contains a control character: %q", health.LastError)
	}

	// A checkpoint below the poison does not make the read model healthy.
	if err := s.AdvanceProjectionCheckpoint(ctx, 10); err != nil {
		t.Fatalf("advance below failure: %v", err)
	}
	health, err = s.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.AppliedSequence != 10 || health.FailedSequence != 11 || health.LastError == "" {
		t.Fatalf("advance below failure cleared it: %+v", health)
	}

	// A stale replica must not paint an already-covered older sequence red.
	if err := s.RecordProjectionTailFailure(ctx, 9, errors.New("stale replica")); err != nil {
		t.Fatalf("record stale failure: %v", err)
	}
	health, err = s.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.FailedSequence != 11 || health.LastError == "stale replica" {
		t.Fatalf("stale failure replaced the live poison: %+v", health)
	}

	// Crossing the failed sequence advances and clears atomically.
	if err := s.AdvanceProjectionCheckpoint(ctx, 11); err != nil {
		t.Fatalf("advance through failure: %v", err)
	}
	health, err = s.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.AppliedSequence != 11 || health.FailedSequence != 0 || health.LastError != "" || health.FailedAt != nil {
		t.Fatalf("covered failure was not cleared with checkpoint: %+v", health)
	}
}

// TestProjectionTailHealthExactCheckpointAndRebuildReset covers the other two
// checkpoint writers. Snapshot/rebuild catch-up may set an exact cursor, and a
// full rebuild starts a fresh health epoch inside its all-or-nothing transaction.
func TestProjectionTailHealthExactCheckpointAndRebuildReset(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	resetProjectionTailHealthFixture(t, s)

	if err := s.RecordProjectionTailFailure(ctx, 20, errors.New("poison")); err != nil {
		t.Fatal(err)
	}
	withProjectionCheckpointTx(t, s, func(tx pgx.Tx) error {
		return s.SetProjectionCheckpointTx(ctx, tx, 19)
	})
	health, err := s.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.FailedSequence != 20 {
		t.Fatalf("exact checkpoint below poison cleared failure: %+v", health)
	}

	withProjectionCheckpointTx(t, s, func(tx pgx.Tx) error {
		return s.SetProjectionCheckpointTx(ctx, tx, 20)
	})
	health, err = s.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.AppliedSequence != 20 || health.FailedSequence != 0 {
		t.Fatalf("exact checkpoint through poison did not clear it: %+v", health)
	}

	if err := s.RecordProjectionTailFailure(ctx, 21, errors.New("rebuild poison")); err != nil {
		t.Fatal(err)
	}
	withProjectionCheckpointTx(t, s, func(tx pgx.Tx) error {
		return s.ResetProjectionCheckpointTx(ctx, tx)
	})
	health, err = s.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.AppliedSequence != 0 || health.FailedSequence != 0 || health.LastError != "" || health.FailedAt != nil {
		t.Fatalf("successful rebuild reset did not start a fresh health epoch: %+v", health)
	}
}

// TestProjectionTailHealthOldWriterAdvanceNormalizesFailure proves a migrated
// database remains safe while an older process is still running. That process
// knows only applied_seq and issues raw SQL; PostgreSQL itself must retain a poison
// below the cursor and clear it when that old writer advances through the poison.
func TestProjectionTailHealthOldWriterAdvanceNormalizesFailure(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	resetProjectionTailHealthFixture(t, s)

	if err := s.AdvanceProjectionCheckpoint(ctx, 4); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordProjectionTailFailure(ctx, 8, errors.New("mixed-version poison")); err != nil {
		t.Fatal(err)
	}

	// This is intentionally NOT a Store method. It is the exact UPDATE emitted by
	// binaries that predate the health columns.
	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE projection_checkpoint SET applied_seq = 7, updated_at = now() WHERE id = 1`); err != nil {
		t.Fatalf("old writer advance below poison: %v", err)
	}
	health, err := s.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.AppliedSequence != 7 || health.FailedSequence != 8 {
		t.Fatalf("old writer below poison broke health: %+v", health)
	}

	if _, err := s.SystemPool().Exec(ctx,
		`UPDATE projection_checkpoint SET applied_seq = 8, updated_at = now() WHERE id = 1`); err != nil {
		t.Fatalf("old writer advance through poison: %v", err)
	}
	health, err = s.ProjectionTailHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if health.AppliedSequence != 8 || health.FailedSequence != 0 ||
		health.LastError != "" || health.FailedAt != nil {
		t.Fatalf("database left applied>=failed stale after old-writer advance: %+v", health)
	}
}

func resetProjectionTailHealthFixture(t *testing.T, s *store.Store) {
	t.Helper()
	if _, err := s.SystemPool().Exec(context.Background(),
		`UPDATE projection_checkpoint
		    SET applied_seq = 0, failed_seq = NULL, last_error = NULL,
		        failed_at = NULL, updated_at = now()
		  WHERE id = 1`); err != nil {
		t.Fatalf("reset projection-tail health fixture: %v", err)
	}
}

func withProjectionCheckpointTx(t *testing.T, s *store.Store, fn func(pgx.Tx) error) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.SystemPool().Begin(ctx)
	if err != nil {
		t.Fatalf("begin projection checkpoint tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		t.Fatalf("projection checkpoint tx: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit projection checkpoint tx: %v", err)
	}
}
