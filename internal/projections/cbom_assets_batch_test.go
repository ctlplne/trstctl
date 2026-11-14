// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// X6-O1: cbom.assets.observed applies each observation in order under the
// batch's sequence, as cbom.asset.observed would, and a rebuild reaches the
// same rows; an empty batch, an oversized one and one with an incomplete
// observation are refused.
func TestCBOMAssetsObservedBatchX6O1(t *testing.T) {
	st, log := newStore(t), openLog(t)
	p := projections.New(st)
	if err := p.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	const tenant = "6c3b0000-0000-4000-8000-000000000001"
	appendEvent := func(kind string, payload any) events.Event {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := log.Append(t.Context(), events.Event{TenantID: tenant, Type: kind, Data: data})
		if err != nil {
			t.Fatal(err)
		}
		return stored
	}
	appendEvent("tenant.registered", map[string]string{"name": "CBOM batch owner"})
	observation := func(location, strength string) projections.CBOMAssetObserved {
		asset := store.CryptoAsset{TenantID: tenant, Kind: "imported-algorithm", Location: location, Algorithm: "RSA", KeyBits: 2048}
		return projections.CBOMAssetObserved{ID: store.StableCryptoAssetID(tenant, asset.Signature()), Kind: asset.Kind,
			Location: location, Algorithm: "RSA", KeyBits: 2048, Strength: strength, ImportSource: "image:base:1"}
	}
	first, second := observation("image:base:1:/etc/ssl/a.pem", "weak"), observation("image:base:1:/etc/ssl/b.pem", "acceptable")
	again := first
	again.Strength = "acceptable" // the later observation of the same asset in one batch wins, as a later event would
	appendEvent(projections.EventCBOMAssetsObserved, projections.CBOMAssetsObserved{Assets: []projections.CBOMAssetObserved{first, second, again}})
	if err := p.Project(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	read := func() map[string]string {
		t.Helper()
		assets, err := st.ListCryptoAssets(t.Context(), tenant)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, a := range assets {
			out[a.Location] = a.Strength
		}
		return out
	}
	want := map[string]string{"image:base:1:/etc/ssl/a.pem": "acceptable", "image:base:1:/etc/ssl/b.pem": "acceptable"}
	if got := read(); len(got) != 2 || got["image:base:1:/etc/ssl/a.pem"] != want["image:base:1:/etc/ssl/a.pem"] || got["image:base:1:/etc/ssl/b.pem"] != want["image:base:1:/etc/ssl/b.pem"] {
		t.Fatalf("rows after the batch = %v, want %v", got, want)
	}
	if err := p.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	if got := read(); len(got) != 2 || got["image:base:1:/etc/ssl/a.pem"] != want["image:base:1:/etc/ssl/a.pem"] {
		t.Fatalf("rows after a rebuild = %v, want %v", got, want)
	}

	oversized := make([]projections.CBOMAssetObserved, projections.MaxCBOMAssetsPerEvent+1)
	for i := range oversized {
		oversized[i] = first
	}
	incomplete := second
	incomplete.Strength = ""
	for name, batch := range map[string]projections.CBOMAssetsObserved{
		"empty":      {},
		"oversized":  {Assets: oversized},
		"incomplete": {Assets: []projections.CBOMAssetObserved{first, incomplete}},
	} {
		data, err := json.Marshal(batch)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Apply(t.Context(), events.Event{ID: events.NewID(), TenantID: tenant, Type: projections.EventCBOMAssetsObserved,
			Data: data, Sequence: 9000}); err == nil {
			t.Fatalf("a %s batch was applied", name)
		}
	}
}
