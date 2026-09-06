// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A later run of the same source that observes the same credential refreshes the
// existing finding instead of opening a duplicate: the row keeps its identity and
// triage state, moves to the latest run, and records first/last seen and a count.
func TestDiscoveryFindingReobservationRefreshesOneRow(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const (
		sourceID  = "00000000-0000-4000-8000-000000020201"
		run1      = "00000000-0000-4000-8000-000000020202"
		run2      = "00000000-0000-4000-8000-000000020203"
		findingID = "00000000-0000-4000-8000-000000020204"
		event1    = "00000000-0000-4000-8000-000000020205"
		event2    = "00000000-0000-4000-8000-000000020206"
		event3    = "00000000-0000-4000-8000-000000020207"
	)
	t1 := time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)
	t2 := t1.Add(2 * time.Hour)
	if err := s.UpsertTenant(ctx, store.Tenant{TenantID: tenantA, Name: "Acme"}); err != nil {
		t.Fatal(err)
	}
	seedRun := func(tx pgx.Tx, runID string) error {
		return s.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{
			ID: runID, TenantID: tenantA, SourceID: sourceID, Status: "queued", CreatedAt: t1,
		})
	}
	observation := func(runID, recordedID string, sequence int64, at time.Time, meta string) store.DiscoveryFinding {
		return store.DiscoveryFinding{
			ID: findingID, RecordedID: recordedID, TenantID: tenantA, RunID: runID, SourceID: sourceID,
			Kind: "x509_certificate", Ref: "edge.example.test:443", Provenance: "network-relay:edge:edge.example.test:443",
			Fingerprint: "sha256:same", RiskScore: 40, Metadata: []byte(meta), DiscoveredAt: at,
			ProjectionEventSequence: sequence,
		}
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sourceID, TenantID: tenantA, Kind: "network", Name: "edge-net",
			Config: []byte(`{}`), CreatedAt: t1, UpdatedAt: t1,
		}); err != nil {
			return err
		}
		if err := seedRun(tx, run1); err != nil {
			return err
		}
		if err := seedRun(tx, run2); err != nil {
			return err
		}
		if err := s.ApplyDiscoveryFindingRecordedTx(ctx, tx, observation(run1, event1, 10, t1, `{"not_after":"2026-12-01T00:00:00Z"}`)); err != nil {
			return err
		}
		if err := s.ApplyDiscoveryFindingTriageChangedTx(ctx, tx, store.DiscoveryFindingTriageChange{
			TenantID: tenantA, FindingID: findingID, Status: "investigating", Actor: "ops", Reason: "looking", ChangedAt: t1,
		}); err != nil {
			return err
		}
		// The second run sees the same listener again, with refreshed observation metadata.
		return s.ApplyDiscoveryFindingRecordedTx(ctx, tx, observation(run2, event2, 20, t2, `{"not_after":"2026-12-01T00:00:00Z","seen_by":"run2"}`))
	}); err != nil {
		t.Fatalf("seed and re-observe: %v", err)
	}

	rows, err := s.ListDiscoveryFindingsPage(ctx, tenantA, "", "00000000-0000-0000-0000-000000000000", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("findings after re-observation = %d, want exactly one row", len(rows))
	}
	got := rows[0]
	if got.ID != findingID || got.RunID != run2 || got.SeenCount != 2 {
		t.Fatalf("row = id %s run %s seen %d, want the same row on run %s seen twice", got.ID, got.RunID, got.SeenCount, run2)
	}
	if !got.FirstSeenAt.Equal(t1) || !got.LastSeenAt.Equal(t2) || !got.DiscoveredAt.Equal(t1) {
		t.Fatalf("first/last/discovered = %s/%s/%s, want %s/%s/%s", got.FirstSeenAt, got.LastSeenAt, got.DiscoveredAt, t1, t2, t1)
	}
	if got.TriageStatus != "investigating" {
		t.Fatalf("triage state after re-observation = %q, want the operator's decision kept", got.TriageStatus)
	}
	if !strings.Contains(string(got.Metadata), `"seen_by"`) {
		t.Fatalf("metadata was not refreshed to the latest observation: %s", got.Metadata)
	}
	// The second run's findings page and the first run's page both resolve to the one row.
	byRun2, err := s.ListDiscoveryFindingsPage(ctx, tenantA, run2, "00000000-0000-0000-0000-000000000000", 10)
	if err != nil || len(byRun2) != 1 {
		t.Fatalf("findings for the latest run = %d (%v), want 1", len(byRun2), err)
	}

	// Replaying the already-projected event (catch-up at the same log sequence) changes nothing.
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDiscoveryFindingRecordedTx(ctx, tx, observation(run2, event2, 20, t2, `{"not_after":"2026-12-01T00:00:00Z","seen_by":"run2"}`))
	}); err != nil {
		t.Fatalf("replay of a projected event: %v", err)
	}
	again, err := s.GetDiscoveryFinding(ctx, tenantA, findingID)
	if err != nil {
		t.Fatal(err)
	}
	if again.SeenCount != 2 || !again.LastSeenAt.Equal(t2) {
		t.Fatalf("replay changed the row: seen %d last %s", again.SeenCount, again.LastSeenAt)
	}

	// A same-run payload that disagrees on the immutable observation is still a conflict.
	err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDiscoveryFindingRecordedTx(ctx, tx, observation(run2, event3, 30, t2, `{"not_after":"2027-01-01T00:00:00Z"}`))
	})
	if !errors.Is(err, store.ErrDiscoveryFindingConflict) {
		t.Fatalf("same-run divergent payload error = %v, want ErrDiscoveryFindingConflict", err)
	}
}
