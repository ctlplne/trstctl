// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// A172-L2: the findings filter selects every finding that names one
// fingerprint, across kinds, sources and runs, and pages them by id.
func TestDiscoveryFindingFilterSelectsByFingerprintA172L2(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const shared = "a172l2-1111111111111111111111111111111111111111111111111111111111111111"
	sourceA, sourceB, runA, runB := uuid(tenantA, 1721), uuid(tenantA, 1722), uuid(tenantA, 1723), uuid(tenantA, 1724)
	findings := []struct {
		id, source, run, kind, fingerprint string
	}{
		{uuid(tenantA, 1731), sourceA, runA, "certificate", shared},
		{uuid(tenantA, 1732), sourceB, runB, "private_key", shared},
		{uuid(tenantA, 1733), sourceB, runB, "certificate", "a172l2-other"},
		{uuid(tenantA, 1734), sourceA, runA, "trust-store", shared},
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		for i, src := range []string{sourceA, sourceB} {
			if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
				ID: src, TenantID: tenantA, Kind: []string{"network", "host"}[i], Name: "a172l2-" + src, Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				return err
			}
		}
		for _, run := range []struct{ id, source string }{{runA, sourceA}, {runB, sourceB}} {
			if err := s.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{ID: run.id, TenantID: tenantA, SourceID: run.source, Status: "queued", CreatedAt: now}); err != nil {
				return err
			}
		}
		for _, f := range findings {
			if err := s.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{
				ID: f.id, TenantID: tenantA, RunID: f.run, SourceID: f.source, Kind: f.kind, Ref: "ref-" + f.id,
				Provenance: "a172l2", Fingerprint: f.fingerprint, RiskScore: 30, Metadata: []byte(`{}`), DiscoveredAt: now,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed findings: %v", err)
	}
	page := func(after string, limit int) []string {
		t.Helper()
		rows, err := s.ListDiscoveryFindingsFiltered(ctx, tenantA, store.DiscoveryFindingFilter{Fingerprint: shared}, after, limit)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(rows))
		for _, r := range rows {
			if r.Fingerprint != shared {
				t.Fatalf("finding %s has fingerprint %q", r.ID, r.Fingerprint)
			}
			ids = append(ids, r.ID)
		}
		return ids
	}
	all := page(store.ZeroUUID, 100)
	want := []string{findings[0].id, findings[1].id, findings[3].id}
	slices.Sort(want)
	if !slices.Equal(all, want) {
		t.Fatalf("findings with the fingerprint = %v; want %v (every kind, source and run)", all, want)
	}
	first := page(store.ZeroUUID, 2)
	if len(first) != 2 || !slices.Equal(append(first, page(first[1], 2)...), want) {
		t.Fatalf("pages = %v then %v; want the same three in id order", first, page(first[1], 2))
	}
}
