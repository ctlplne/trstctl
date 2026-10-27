// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

// The discovery findings filter selects by the key verdict a reader recorded: the
// distrust-list entry it matched, or a weak key.
func TestDiscoveryFindingFilterSelectsByKeyVerdict(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sourceID, runID := uuid(tenantA, 1841), uuid(tenantA, 1842)
	metas := []string{
		`{"distrust_entry":"emSign ECC Root CA - G3","distrust_how":"itself"}`,
		`{"key_strength":"weak","key_weak_reason":"RSA-1024 is below the 2048-bit minimum"}`,
		`{"distrust_entry":"Another Entry","key_strength":"weak"}`,
		`{}`,
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: sourceID, TenantID: tenantA, Kind: "trust-store", Name: "verdict-filter", Config: []byte(`{}`), CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		if err := s.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{ID: runID, TenantID: tenantA, SourceID: sourceID, Status: "queued", CreatedAt: now}); err != nil {
			return err
		}
		for i, meta := range metas {
			id := uuid(tenantA, 1850+i)
			if err := s.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{
				ID: id, TenantID: tenantA, RunID: runID, SourceID: sourceID, Kind: "trust-store", Ref: "ref-" + id,
				Provenance: "verdict-filter", Fingerprint: "fp-" + id, RiskScore: 40, Metadata: []byte(meta), DiscoveredAt: now,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed findings: %v", err)
	}
	list := func(filter store.DiscoveryFindingFilter) []string {
		t.Helper()
		filter.RunID = runID
		rows, err := s.ListDiscoveryFindingsFiltered(ctx, tenantA, filter, store.ZeroUUID, 100)
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(rows))
		for _, r := range rows {
			ids = append(ids, r.ID)
		}
		return ids
	}
	if got := list(store.DiscoveryFindingFilter{DistrustEntry: "emSign ECC Root CA - G3"}); len(got) != 1 || got[0] != uuid(tenantA, 1850) {
		t.Fatalf("distrust entry filter = %v", got)
	}
	if got := list(store.DiscoveryFindingFilter{KeyStrength: "weak"}); len(got) != 2 || got[0] != uuid(tenantA, 1851) || got[1] != uuid(tenantA, 1852) {
		t.Fatalf("weak key filter = %v", got)
	}
	if got := list(store.DiscoveryFindingFilter{DistrustEntry: "Another Entry", KeyStrength: "weak"}); len(got) != 1 || got[0] != uuid(tenantA, 1852) {
		t.Fatalf("both filters = %v", got)
	}
	if got := list(store.DiscoveryFindingFilter{}); len(got) != len(metas) {
		t.Fatalf("no verdict filter = %v", got)
	}
	if got := list(store.DiscoveryFindingFilter{DistrustEntry: "emsign ecc root ca - g3"}); len(got) != 0 {
		t.Fatalf("the entry name is matched exactly, as the reader recorded it: %v", got)
	}
}
