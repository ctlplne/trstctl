// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/migration"
)

func TestMigrationRunProjectionIsTenantScopedAndMonotonicAUD40(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	runID := "40400000-0000-4000-8000-000000000001"
	newer := migration.Run{ID: runID, Status: migration.RunRunning, Waves: []migration.RunWave{{
		ID: "canary", Ordinal: 1, Phase: migration.PhaseVerifyingTrust,
		Members: []migration.RunMember{{IdentityID: "identity-a"}},
	}}}
	at := time.Date(2026, 8, 12, 1, 2, 3, 0, time.UTC)
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyMigrationRunRecordedTx(ctx, tx, tenantA, newer, 2, at)
	}); err != nil {
		t.Fatal(err)
	}
	stale := newer
	stale.Status = migration.RunPlanned
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyMigrationRunRecordedTx(ctx, tx, tenantA, stale, 1, at.Add(-time.Minute))
	}); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetMigrationRun(ctx, tenantA, runID)
	if err != nil || got.Run.Status != migration.RunRunning || got.LastEventSequence != 2 {
		t.Fatalf("projected run = %+v, err=%v", got, err)
	}
	if _, err := st.GetMigrationRun(ctx, tenantB, runID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("tenant B read tenant A migration = %v", err)
	}
}
