// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestCryptoAssetMigrationMergesExistingDesiredSignatureUnderTenantRLS(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	seedTwoTenants(t, st)

	weak := store.CryptoAsset{
		ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", TenantID: tenantA,
		Kind: "host-config", Location: "/etc/envoy/listener.conf", Protocol: "TLSv1",
		Strength: "weak", QuantumVulnerable: true, OutOfPolicy: true,
	}
	approved := weak
	approved.ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	approved.Protocol = "TLSv1.3"
	approved.Strength = "strong"
	approved.QuantumVulnerable = false
	approved.OutOfPolicy = false
	foreign := approved
	foreign.ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	foreign.TenantID = tenantB

	for _, asset := range []store.CryptoAsset{weak, approved, foreign} {
		if _, err := st.UpsertCryptoAsset(ctx, asset); err != nil {
			t.Fatalf("seed crypto asset %s: %v", asset.ID, err)
		}
	}

	migrated := weak
	migrated.Protocol = approved.Protocol
	migrated.Strength = approved.Strength
	migrated.QuantumVulnerable = false
	migrated.OutOfPolicy = false
	migrated.Reasons = []string{"migration read-back verified"}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyCryptoAssetMigratedTx(ctx, tx, migrated, migrated.CreatedAt)
	}); err != nil {
		t.Fatalf("project colliding desired signature: %v", err)
	}

	gotA, err := st.ListCryptoAssets(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotA) != 1 || gotA[0].ID != approved.ID || gotA[0].Protocol != "TLSv1.3" || gotA[0].OutOfPolicy {
		t.Fatalf("tenant A merged projection = %+v, want canonical compliant TLSv1.3 fact", gotA)
	}
	gotB, err := st.ListCryptoAssets(ctx, tenantB)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotB) != 1 || gotB[0].ID != foreign.ID {
		t.Fatalf("tenant B projection changed across RLS boundary: %+v", gotB)
	}

	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyCryptoAssetRolledBackTx(ctx, tx, weak, weak.CreatedAt)
	}); err != nil {
		t.Fatalf("restore merged weak finding: %v", err)
	}
	gotA, err = st.ListCryptoAssets(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotA) != 2 {
		t.Fatalf("tenant A rollback projection = %+v, want canonical approved plus restored weak fact", gotA)
	}
	byID := map[string]store.CryptoAsset{}
	for _, asset := range gotA {
		byID[asset.ID] = asset
	}
	if byID[weak.ID].Protocol != "TLSv1" || !byID[weak.ID].OutOfPolicy || byID[approved.ID].Protocol != "TLSv1.3" {
		t.Fatalf("tenant A rollback did not restore exact facts: %+v", gotA)
	}
}
