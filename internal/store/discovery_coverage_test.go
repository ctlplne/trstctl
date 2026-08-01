// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// TestDiscoveryCoverageProjectionAndTenantScope projects a source upsert and a
// completed run into the coverage rollup, reads it back tenant-scoped, and
// proves the cross-tenant read returns zero rows (AN-1) and that a stale
// replay cannot regress a newer row (AN-2 at-least-once idempotency).
func TestDiscoveryCoverageProjectionAndTenantScope(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	sourceID := uuid(tenantA, 501)
	runID := uuid(tenantA, 502)
	completedAt := time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC)

	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sourceID, TenantID: tenantA, Kind: "network", Name: "dc-ranges",
			Config: []byte(`{}`), CreatedAt: completedAt, UpdatedAt: completedAt,
		}); err != nil {
			return err
		}
		if err := s.ApplyDiscoveryCoverageSourceTx(ctx, tx, store.DiscoveryCoverage{
			TenantID: tenantA, SourceID: sourceID, SourceKind: "network",
			SourceName: "dc-ranges", EventSequence: 10,
		}); err != nil {
			return err
		}
		if err := s.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
			ID: runID, TenantID: tenantA, SourceID: sourceID, Status: "queued", CreatedAt: completedAt,
		}); err != nil {
			return err
		}
		if err := s.ApplyDiscoveryRunCompletedTx(ctx, tx, store.DiscoveryRun{
			ID: runID, TenantID: tenantA, Status: "succeeded", Targets: 4, Discovered: 4,
			CompletedAt: &completedAt,
		}); err != nil {
			return err
		}
		return s.ApplyDiscoveryCoverageRunTx(ctx, tx, tenantA, runID, "succeeded", completedAt, 11)
	}); err != nil {
		t.Fatalf("seed coverage rollup: %v", err)
	}

	rows, err := s.ListDiscoveryCoverage(ctx, tenantA)
	if err != nil {
		t.Fatalf("ListDiscoveryCoverage(A): %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("tenant A coverage rows = %d, want 1", len(rows))
	}
	got := rows[0]
	if got.SourceKind != "network" || got.SourceName != "dc-ranges" ||
		got.LastRunStatus != "succeeded" || got.EventSequence != 11 {
		t.Fatalf("coverage row = %+v", got)
	}
	if got.LastCompletedAt == nil || !got.LastCompletedAt.Equal(completedAt) {
		t.Fatalf("last completed at = %v, want %v", got.LastCompletedAt, completedAt)
	}

	// AN-1: the other tenant sees nothing.
	if bRows, err := s.ListDiscoveryCoverage(ctx, tenantB); err != nil || len(bRows) != 0 {
		t.Fatalf("cross-tenant ListDiscoveryCoverage = (%d rows, %v), want 0 rows", len(bRows), err)
	}

	// AN-2: a stale replay (lower sequence, different name) cannot regress.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDiscoveryCoverageSourceTx(ctx, tx, store.DiscoveryCoverage{
			TenantID: tenantA, SourceID: sourceID, SourceKind: "network",
			SourceName: "stale-name", EventSequence: 5,
		})
	}); err != nil {
		t.Fatalf("stale replay: %v", err)
	}
	rows, err = s.ListDiscoveryCoverage(ctx, tenantA)
	if err != nil || len(rows) != 1 {
		t.Fatalf("after stale replay: rows=%d err=%v", len(rows), err)
	}
	if rows[0].SourceName != "dc-ranges" || rows[0].EventSequence != 11 {
		t.Fatalf("stale replay regressed the row: %+v", rows[0])
	}
}
