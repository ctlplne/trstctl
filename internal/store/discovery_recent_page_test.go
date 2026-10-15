// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestDiscoveryRunsRecentPageIsTenantBoundAndStableAcrossTies(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	const sourceID = "73737373-0000-4000-8000-000000000001"
	const otherSourceID = "73737373-0000-4000-8000-000000000005"
	seed := func(tenant, source, name string, runs []store.DiscoveryRun) {
		t.Helper()
		if err := st.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			if err := st.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
				ID: source, TenantID: tenant, Kind: "network", Name: name,
				Config: []byte(`{"targets":["192.0.2.1:443"]}`), CreatedAt: base, UpdatedAt: base,
			}); err != nil {
				return err
			}
			for _, run := range runs {
				if err := st.ApplyDiscoveryRunQueuedTx(ctx, tx, run); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("seed %s: %v", tenant, err)
		}
	}
	newRun := func(tenant, source, id string, created time.Time) store.DiscoveryRun {
		return store.DiscoveryRun{ID: id, TenantID: tenant, SourceID: source,
			Status: "queued", RequestedBy: "test", Execution: "relay", Segment: "test", CreatedAt: created}
	}
	const older = "73737373-0000-4000-8000-000000000099"
	const tiedLow = "73737373-0000-4000-8000-000000000002"
	const tiedHigh = "73737373-0000-4000-8000-000000000003"
	seed(tenantA, sourceID, "recent-page-a", []store.DiscoveryRun{
		newRun(tenantA, sourceID, older, base),
		newRun(tenantA, sourceID, tiedLow, base.Add(time.Minute)),
		newRun(tenantA, sourceID, tiedHigh, base.Add(time.Minute)),
	})
	seed(tenantB, otherSourceID, "recent-page-b", []store.DiscoveryRun{
		newRun(tenantB, otherSourceID, "73737373-0000-4000-8000-000000000004", base.Add(2*time.Minute)),
	})

	first, err := st.ListDiscoveryRunsRecentPage(ctx, tenantA, store.ZeroUUID, 2)
	if err != nil || len(first) != 2 || first[0].ID != tiedHigh || first[1].ID != tiedLow {
		t.Fatalf("first recent page = %v, err %v", first, err)
	}
	second, err := st.ListDiscoveryRunsRecentPage(ctx, tenantA, first[1].ID, 2)
	if err != nil || len(second) != 1 || second[0].ID != older {
		t.Fatalf("second recent page = %v, err %v", second, err)
	}
	otherTenantCursor, err := st.ListDiscoveryRunsRecentPage(ctx, tenantA, "73737373-0000-4000-8000-000000000004", 2)
	if err != nil || len(otherTenantCursor) != 0 {
		t.Fatalf("cross-tenant cursor page = %v, err %v", otherTenantCursor, err)
	}
}
