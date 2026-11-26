// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/store"
)

func TestDiscoveryMonitoringPagesBoundConfigAndTenant(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	ids := []string{uuid(tenantA, 2701), uuid(tenantA, 2702), uuid(tenantA, 2703)}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		for i, id := range ids {
			payloadSize := 64000
			if i == 2 {
				payloadSize = 128000 // a legacy declaration that predates the admission limit
			}
			if err := s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
				ID: id, TenantID: tenantA, Kind: "manual", Name: id,
				Config:    []byte(`{"findings":[{"note":"` + strings.Repeat("x", payloadSize) + `"}]}`),
				CreatedAt: now, UpdatedAt: now,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	first, err := s.ListDiscoveryMonitoringSourcesPage(ctx, tenantA, store.ZeroUUID, 2)
	if err != nil || len(first) != 2 || first[0].SourceID != ids[0] || first[1].SourceID != ids[1] {
		t.Fatalf("first page: %d rows, err=%v", len(first), err)
	}
	if len(first[0].Config) == 0 || len(first[1].Config) == 0 {
		t.Fatal("bounded source configs were omitted from the monitoring page")
	}
	second, err := s.ListDiscoveryMonitoringSourcesPage(ctx, tenantA, first[1].SourceID, 2)
	if err != nil || len(second) != 1 || second[0].SourceID != ids[2] {
		t.Fatalf("second page: %d rows, err=%v", len(second), err)
	}
	if len(second[0].Config) != 0 {
		t.Fatal("oversized legacy config was returned by the monitoring query")
	}
	other, err := s.ListDiscoveryMonitoringSourcesPage(ctx, tenantB, store.ZeroUUID, 2)
	if err != nil || len(other) != 0 {
		t.Fatalf("cross-tenant page: %d rows, err=%v", len(other), err)
	}
	if _, err := s.ListDiscoveryMonitoringSourcesPage(ctx, tenantA, store.ZeroUUID, 101); err == nil {
		t.Fatal("unbounded page accepted")
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{
			ID: uuid(tenantA, 2704), TenantID: tenantA, Kind: "adcs", Name: "adcs-monitoring",
			Config: []byte(`{"directory":"example.test"}`), CreatedAt: now, UpdatedAt: now,
		})
	}); err != nil {
		t.Fatal(err)
	}
	adcs, err := s.ListADCSDiscoveryMonitoringSourcesPage(ctx, tenantA, store.ZeroUUID, 100)
	if err != nil || len(adcs) != 1 || adcs[0].Kind != "adcs" || len(adcs[0].Config) != 0 {
		t.Fatalf("AD CS metadata page returned unrelated sources or config: %d rows, err=%v", len(adcs), err)
	}
}
