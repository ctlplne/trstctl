// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestCBOMProductDefaultsAreTheirOwnFactsX2L7: a host-config fact a product
// reaches only through its built-in default (cbom.asset.observed with
// config_source default and product_version) projects as its own row beside
// the same value stated in a file; the stated fact keeps the identity it had
// before defaults existed, and an event from before them projects as stated.
// A snapshot restore and an event-only rebuild reach the same rows.
func TestCBOMProductDefaultsAreTheirOwnFactsX2L7(t *testing.T) {
	// Its own tenant: the package's other CBOM tests record tenantA's rows in
	// the same database.
	const tenant = "27a70000-0000-4000-8000-0000000027a7"
	st, log := newStore(t), openLog(t)
	p := projections.New(st)
	ctx := t.Context()
	appendEvent := func(kind string, payload any) {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := log.Append(ctx, events.Event{TenantID: tenant, Type: kind, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
	appendEvent("tenant.registered", map[string]string{"name": "X2-L7 product defaults"})
	const path = "/etc/haproxy/haproxy.cfg"
	stated := store.CryptoAsset{TenantID: tenant, Kind: "host-config", Location: path, Protocol: "TLSv1.2"}
	// The identity a stated fact always had: its signature names no source.
	statedID := store.StableCryptoAssetID(tenant, "host-config|"+path+"||0|TLSv1.2|")
	if store.StableCryptoAssetID(tenant, stated.Signature()) != statedID {
		t.Fatal("a stated fact's identity moved")
	}
	defaulted := stated
	defaulted.ConfigSource, defaulted.ProductVersion = "default", "haproxy 2.8.5-1ubuntu3"
	defaultID := store.StableCryptoAssetID(tenant, defaulted.Signature())
	if defaultID == statedID {
		t.Fatal("a product default shares the stated fact's identity")
	}
	// The stated fact as an event from before X2-L7 carried it (no fields).
	appendEvent(projections.EventCBOMAssetObserved, map[string]any{"id": statedID, "kind": "host-config", "location": path,
		"protocol": "TLSv1.2", "library": "haproxy", "strength": "acceptable", "quantum_vulnerable": false, "out_of_policy": false})
	appendEvent(projections.EventCBOMAssetObserved, projections.CBOMAssetObserved{ID: defaultID, Kind: "host-config", Location: path,
		Protocol: "TLSv1.2", Library: "haproxy", Strength: "acceptable", ConfigSource: "default", ProductVersion: "haproxy 2.8.5-1ubuntu3"})
	group := defaulted
	group.Protocol, group.Algorithm, group.ProductVersion = "", "X25519MLKEM768", "libssl3 3.5.9-r0"
	groupID := store.StableCryptoAssetID(tenant, group.Signature())
	appendEvent(projections.EventCBOMAssetObserved, projections.CBOMAssetObserved{ID: groupID, Kind: "host-config", Location: path,
		Algorithm: "X25519MLKEM768", Library: "haproxy", Strength: "strong", ConfigSource: "default", ProductVersion: "libssl3 3.5.9-r0"})
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	want := []string{
		defaultID + "|TLSv1.2|default|haproxy 2.8.5-1ubuntu3",
		groupID + "|X25519MLKEM768|default|libssl3 3.5.9-r0",
		statedID + "|TLSv1.2||",
	}
	sort.Strings(want)
	check := func(stage string) {
		t.Helper()
		assets, err := st.ListCryptoAssets(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, a := range assets {
			got = append(got, strings.Join([]string{a.ID, a.Protocol + a.Algorithm, a.ConfigSource, a.ProductVersion}, "|"))
		}
		sort.Strings(got)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("%s:\n got %q\nwant %q", stage, got, want)
		}
	}
	check("projection")
	if _, err := p.Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	truncateReadModelAndCheckpoint(t, st)
	if _, err := p.RestoreFromSnapshot(ctx, log); err != nil {
		t.Fatal(err)
	}
	check("snapshot restore")
	if err := p.Rebuild(ctx, log); err != nil {
		t.Fatal(err)
	}
	check("event-only rebuild")
}
