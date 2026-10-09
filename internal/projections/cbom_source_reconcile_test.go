// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func TestCBOMSourceReconciliationReplaysAndStaysTenantScoped(t *testing.T) {
	st, log := newStore(t), openLog(t)
	p := projections.New(st)
	if err := p.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	appendPQCObservationEvent(t, log, tenantA, "tenant.registered", map[string]string{"name": "CBOM owner"})
	appendPQCObservationEvent(t, log, tenantB, "tenant.registered", map[string]string{"name": "CBOM neighbor"})
	if err := p.Project(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	const location = "/etc/nginx/tls.conf"
	observe := func(tenant, protocol string) string {
		t.Helper()
		asset := store.CryptoAsset{TenantID: tenant, Kind: "host-config", Location: location, Protocol: protocol}
		id := store.StableCryptoAssetID(tenant, asset.Signature())
		appendPQCObservationEvent(t, log, tenant, projections.EventCBOMAssetObserved, projections.CBOMAssetObserved{
			ID: id, Kind: asset.Kind, Location: location, Protocol: protocol, Strength: "strong",
		})
		return id
	}
	observe(tenantA, "TLSv1.0")
	strongID := observe(tenantA, "TLSv1.3")
	observe(tenantB, "TLSv1.0")
	appendPQCObservationEvent(t, log, tenantA, projections.EventCBOMSourceReconciled, projections.CBOMSourceReconciled{
		SourceKind: "host-config", Location: location, ObservedAssetIDs: []string{strongID},
	})
	if err := p.Project(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	assertAssets := func(tenant, protocol string) {
		t.Helper()
		assets, err := st.ListCryptoAssets(t.Context(), tenant)
		if err != nil || len(assets) != 1 || assets[0].Protocol != protocol {
			t.Fatalf("tenant %s active assets = %+v, err=%v; want only %s", tenant, assets, err, protocol)
		}
	}
	assertAssets(tenantA, "TLSv1.3")
	assertAssets(tenantB, "TLSv1.0")
	// A foreign tenant cannot use a valid UUID from another tenant as evidence
	// for retiring its own location. Reject before any update runs.
	forged := projections.CBOMSourceReconciled{SourceKind: "host-config", Location: location, ObservedAssetIDs: []string{strongID}}
	data, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Apply(t.Context(), events.Event{TenantID: tenantB, Type: projections.EventCBOMSourceReconciled, Sequence: 999, Data: data}); err == nil {
		t.Fatal("foreign asset reference accepted during CBOM reconciliation")
	}
	assertAssets(tenantB, "TLSv1.0")
	if err := p.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	assertAssets(tenantA, "TLSv1.3")
	assertAssets(tenantB, "TLSv1.0")
}
