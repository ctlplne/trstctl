// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// TestDiscoverySchedulesDue exercises the scheduler's due decision against a
// real PostgreSQL under the same RLS the product runs: a schedule is due only
// when enabled, with no in-flight run and no run newer than its interval; a
// failed run still counts as an attempt (retry next interval, never hot-loop);
// and tenants only ever see their own schedules.
func TestDiscoverySchedulesDue(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	seedSchedule := func(tenant, sourceID, schedID string, intervalSeconds int, enabled bool) {
		t.Helper()
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
				ID: sourceID, TenantID: tenant, Name: "src-" + sourceID, Kind: "network",
				Config: []byte(`{}`), CreatedAt: now.Add(-24 * time.Hour), UpdatedAt: now.Add(-24 * time.Hour),
			}); err != nil {
				return err
			}
			return s.ApplyDiscoveryScheduleUpsertedTx(ctx, tx, store.DiscoverySchedule{
				ID: schedID, TenantID: tenant, SourceID: sourceID, Name: "sched-" + schedID,
				IntervalSeconds: intervalSeconds, Enabled: enabled,
				CreatedAt: now.Add(-24 * time.Hour), UpdatedAt: now.Add(-24 * time.Hour),
			})
		}); err != nil {
			t.Fatalf("seed schedule %s: %v", schedID, err)
		}
	}
	seedRun := func(tenant, sourceID, runID, status string, createdAt time.Time) {
		t.Helper()
		if err := s.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return s.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
				ID: runID, TenantID: tenant, SourceID: sourceID, Status: status,
				RequestedBy: "test", CreatedAt: createdAt,
			})
		}); err != nil {
			t.Fatalf("seed run %s: %v", runID, err)
		}
	}

	const hour = 3600

	// Due: never ran.
	seedSchedule(tenantA, "aaaaaaa1-0000-4000-8000-000000000001", "aaaaaaa1-0000-4000-8000-00000000f001", hour, true)
	// Not due: disabled.
	seedSchedule(tenantA, "aaaaaaa1-0000-4000-8000-000000000002", "aaaaaaa1-0000-4000-8000-00000000f002", hour, false)
	// Not due: fresh succeeded run inside the interval.
	seedSchedule(tenantA, "aaaaaaa1-0000-4000-8000-000000000003", "aaaaaaa1-0000-4000-8000-00000000f003", hour, true)
	seedRun(tenantA, "aaaaaaa1-0000-4000-8000-000000000003", "aaaaaaa1-0000-4000-8000-00000000e003", "succeeded", now.Add(-10*time.Minute))
	// Due: last run is older than the interval.
	seedSchedule(tenantA, "aaaaaaa1-0000-4000-8000-000000000004", "aaaaaaa1-0000-4000-8000-00000000f004", hour, true)
	seedRun(tenantA, "aaaaaaa1-0000-4000-8000-000000000004", "aaaaaaa1-0000-4000-8000-00000000e004", "succeeded", now.Add(-2*time.Hour))
	// Not due: an in-flight run exists, even though it is older than the interval.
	seedSchedule(tenantA, "aaaaaaa1-0000-4000-8000-000000000005", "aaaaaaa1-0000-4000-8000-00000000f005", hour, true)
	seedRun(tenantA, "aaaaaaa1-0000-4000-8000-000000000005", "aaaaaaa1-0000-4000-8000-00000000e005", "running", now.Add(-2*time.Hour))
	// Not due: a FAILED run inside the interval counts as an attempt (no hot loop).
	seedSchedule(tenantA, "aaaaaaa1-0000-4000-8000-000000000006", "aaaaaaa1-0000-4000-8000-00000000f006", hour, true)
	seedRun(tenantA, "aaaaaaa1-0000-4000-8000-000000000006", "aaaaaaa1-0000-4000-8000-00000000e006", "failed", now.Add(-10*time.Minute))
	// Tenant isolation: tenant B's due schedule must not leak into A's sweep.
	seedSchedule(tenantB, "bbbbbbb1-0000-4000-8000-000000000001", "bbbbbbb1-0000-4000-8000-00000000f001", hour, true)

	due, err := s.DiscoverySchedulesDue(ctx, tenantA, now, 100)
	if err != nil {
		t.Fatalf("DiscoverySchedulesDue: %v", err)
	}
	got := map[string]bool{}
	for _, d := range due {
		got[d.ID] = true
		if d.TenantID != tenantA {
			t.Fatalf("due schedule %s carries tenant %s, want %s", d.ID, d.TenantID, tenantA)
		}
	}
	want := []string{"aaaaaaa1-0000-4000-8000-00000000f001", "aaaaaaa1-0000-4000-8000-00000000f004"}
	if len(due) != len(want) {
		t.Fatalf("due = %d schedules (%v), want exactly %v", len(due), got, want)
	}
	for _, id := range want {
		if !got[id] {
			t.Fatalf("schedule %s should be due; got %v", id, got)
		}
	}

	// The limit bounds one sweep.
	limited, err := s.DiscoverySchedulesDue(ctx, tenantA, now, 1)
	if err != nil {
		t.Fatalf("DiscoverySchedulesDue limit: %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("limited sweep = %d, want 1", len(limited))
	}

	// Tenant enumeration sees both tenants (cross-tenant system read).
	tenants, err := s.TenantsWithEnabledDiscoverySchedules(ctx)
	if err != nil {
		t.Fatalf("TenantsWithEnabledDiscoverySchedules: %v", err)
	}
	seen := map[string]bool{}
	for _, tn := range tenants {
		seen[tn] = true
	}
	if !seen[tenantA] || !seen[tenantB] {
		t.Fatalf("tenants = %v, want both %s and %s", tenants, tenantA, tenantB)
	}
}
