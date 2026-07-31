// SPDX-License-Identifier: MPL-2.0

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestCryptoAssetMigrationMergesExistingDesiredSignatureUnderTenantRLS(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	seedTwoTenants(t, st)
	now := time.Now().UTC()

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

	for i, asset := range []store.CryptoAsset{weak, approved, foreign} {
		if err := st.WithTenant(ctx, asset.TenantID, func(tx pgx.Tx) error {
			return st.ApplyCryptoAssetObservedTx(ctx, tx, asset, uint64(10+i), now.Add(time.Duration(i)*time.Second))
		}); err != nil {
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
		return st.ApplyCryptoAssetMigratedTx(ctx, tx, migrated, 20, now.Add(10*time.Second))
	}); err != nil {
		t.Fatalf("project colliding desired signature: %v", err)
	}
	// The command-side read-your-write projector and the at-least-once live tail
	// can apply the same completion. A merge that already hid the weak selected
	// row must therefore be a successful no-op on replay, not pgx.ErrNoRows.
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyCryptoAssetMigratedTx(ctx, tx, migrated, 20, now.Add(10*time.Second))
	}); err != nil {
		t.Fatalf("replay colliding desired signature: %v", err)
	}
	// A delayed tail delivery of the older observation must not resurrect the
	// weak fact after the later migration completion has become authoritative.
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyCryptoAssetObservedTx(ctx, tx, weak, 10, now)
	}); err != nil {
		t.Fatalf("replay stale weak observation: %v", err)
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
		return st.ApplyCryptoAssetRolledBackTx(ctx, tx, weak, 30, now.Add(20*time.Second))
	}); err != nil {
		t.Fatalf("restore merged weak finding: %v", err)
	}
	// Once rollback is newer, a delayed completion from the earlier forward run
	// must not hide the restored weak fact again.
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyCryptoAssetMigratedTx(ctx, tx, migrated, 20, now.Add(10*time.Second))
	}); err != nil {
		t.Fatalf("replay stale migration completion: %v", err)
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

func TestCryptoAssetMigrationSequenceRejectsDelayedObservationWithoutDesiredCollision(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	seedTwoTenants(t, st)
	now := time.Now().UTC()
	weak := store.CryptoAsset{
		ID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", TenantID: tenantA,
		Kind: "tls-endpoint", Location: "edge.example:443", Protocol: "TLSv1.0",
		Strength: "weak", QuantumVulnerable: true, OutOfPolicy: true,
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyCryptoAssetObservedTx(ctx, tx, weak, 40, now)
	}); err != nil {
		t.Fatalf("seed weak crypto asset: %v", err)
	}
	migrated := weak
	migrated.Protocol = "TLSv1.3"
	migrated.Strength = "strong"
	migrated.QuantumVulnerable = false
	migrated.OutOfPolicy = false
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyCryptoAssetMigratedTx(ctx, tx, migrated, 50, now.Add(time.Second))
	}); err != nil {
		t.Fatalf("project non-colliding migration: %v", err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyCryptoAssetObservedTx(ctx, tx, weak, 40, now)
	}); err != nil {
		t.Fatalf("replay delayed non-colliding observation: %v", err)
	}
	got, err := st.ListCryptoAssets(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != weak.ID || got[0].Protocol != "TLSv1.3" || got[0].OutOfPolicy {
		t.Fatalf("post-migration inventory = %+v, want one compliant selected fact", got)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyCryptoAssetRolledBackTx(ctx, tx, weak, 60, now.Add(2*time.Second))
	}); err != nil {
		t.Fatalf("rollback non-colliding migration: %v", err)
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return st.ApplyCryptoAssetMigratedTx(ctx, tx, migrated, 50, now.Add(time.Second))
	}); err != nil {
		t.Fatalf("replay delayed non-colliding completion: %v", err)
	}
	got, err = st.ListCryptoAssets(ctx, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Protocol != "TLSv1.0" || !got[0].OutOfPolicy {
		t.Fatalf("post-rollback inventory = %+v, want the newer weak rollback fact", got)
	}
}
