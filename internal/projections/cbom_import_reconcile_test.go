// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// X6-L3: cbom.import.reconciled retires exactly its source's facts that the
// import did not observe again. A row recorded before imports named their
// source is the source's by location, unless a longer import source of the
// tenant owns that location; a scan's row, another source's and another
// tenant's stay. A late redelivery of a retired fact's older observation
// does not revive it, a malformed reconciliation is refused, and a rebuild
// reaches the same state.
func TestCBOMImportReconciliationRetiresOnlyItsSourceX6L3(t *testing.T) {
	st, log := newStore(t), openLog(t)
	p := projections.New(st)
	if err := p.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	appendStored := func(tenant, kind string, payload any) events.Event {
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
	appendStored(tenantA, "tenant.registered", map[string]string{"name": "CBOM import owner"})
	appendStored(tenantB, "tenant.registered", map[string]string{"name": "CBOM import neighbor"})
	for i, source := range []string{"vendor:legacy", "vendor:legacy:fw"} {
		appendStored(tenantA, projections.EventDiscoverySourceUpserted, projections.DiscoverySourceUpserted{
			ID: []string{"6c3a0000-0000-4000-8000-0000000000a1", "6c3a0000-0000-4000-8000-0000000000a2"}[i], Kind: "cbom_import_vendor",
			Name: "cbom-import:" + source, Config: json.RawMessage(`{"source":"` + source + `"}`),
		})
	}
	type observed struct {
		id    string
		event events.Event
	}
	observe := func(tenant, source, kind, location, protocol string) observed {
		t.Helper()
		asset := store.CryptoAsset{TenantID: tenant, Kind: kind, Location: location, Protocol: protocol}
		id := store.StableCryptoAssetID(tenant, asset.Signature())
		return observed{id, appendStored(tenant, projections.EventCBOMAssetObserved, projections.CBOMAssetObserved{
			ID: id, Kind: kind, Location: location, Protocol: protocol, Strength: "weak", ImportSource: source,
		})}
	}
	// Recorded before imports named their source.
	legacyDropped := observe(tenantA, "", "imported-protocol", "vendor:legacy:proto:tls10", "TLSv1.0")
	observe(tenantA, "", "imported-protocol", "vendor:legacy:proto:tls13", "TLSv1.3")
	firmware := observe(tenantA, "", "imported-protocol", "vendor:legacy:fw:proto:tls10", "TLSv1.0")
	scanned := observe(tenantA, "", "host-config", "vendor:legacy:notes", "TLSv1.0")
	neighbor := observe(tenantB, "vendor:legacy", "imported-protocol", "vendor:legacy:proto:tls10", "TLSv1.0")
	// The source's new import observes TLS 1.3 again, then reconciles.
	kept := observe(tenantA, "vendor:legacy", "imported-protocol", "vendor:legacy:proto:tls13", "TLSv1.3")
	reconciled := appendStored(tenantA, projections.EventCBOMImportReconciled, projections.CBOMImportReconciled{
		Source: "vendor:legacy", RunID: "6c3a0000-0000-4000-8000-0000000000b1", ObservedFromSequence: kept.event.Sequence,
	})
	if err := p.Project(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	activeIDs := func(tenant string) string {
		t.Helper()
		assets, err := st.ListCryptoAssets(t.Context(), tenant)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, a := range assets {
			ids = append(ids, a.ID)
		}
		return strings.Join(ids, " ")
	}
	expect := func(step string) {
		t.Helper()
		got := activeIDs(tenantA)
		for _, keep := range []string{kept.id, firmware.id, scanned.id} {
			if !strings.Contains(got, keep) {
				t.Fatalf("%s: %s was retired; active %s", step, keep, got)
			}
		}
		if strings.Contains(got, legacyDropped.id) {
			t.Fatalf("%s: the dropped pre-source TLS 1.0 row is still active", step)
		}
		if activeIDs(tenantB) != neighbor.id {
			t.Fatalf("%s: tenant B's row was touched: %s", step, activeIDs(tenantB))
		}
	}
	expect("after the reconciliation")
	retired, err := st.CryptoAssetIDsRetiredByImport(t.Context(), tenantA, "vendor:legacy", reconciled.Sequence)
	if err != nil || strings.Join(retired, " ") != legacyDropped.id {
		t.Fatalf("retired by the reconciliation = %v, err=%v; want only %s", retired, err, legacyDropped.id)
	}

	// The tail worker may deliver the dropped fact's older observation again.
	if err := p.Apply(t.Context(), legacyDropped.event); err != nil {
		t.Fatal(err)
	}
	expect("after a late redelivery")

	for _, bad := range []struct {
		name    string
		payload projections.CBOMImportReconciled
		seq     uint64
	}{
		{"no observations", projections.CBOMImportReconciled{Source: "vendor:legacy", ObservedFromSequence: 0}, reconciled.Sequence + 10},
		{"observed after itself", projections.CBOMImportReconciled{Source: "vendor:legacy", ObservedFromSequence: reconciled.Sequence + 10}, reconciled.Sequence + 10},
		{"no source", projections.CBOMImportReconciled{ObservedFromSequence: kept.event.Sequence}, reconciled.Sequence + 10},
	} {
		data, err := json.Marshal(bad.payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Apply(t.Context(), events.Event{TenantID: tenantA, Type: projections.EventCBOMImportReconciled, Sequence: bad.seq, Data: data}); err == nil {
			t.Fatalf("a reconciliation with %s was applied", bad.name)
		}
	}
	expect("after the refused reconciliations")

	if err := p.Rebuild(t.Context(), log); err != nil {
		t.Fatal(err)
	}
	expect("after a rebuild")
}
