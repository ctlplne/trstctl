// SPDX-License-Identifier: BUSL-1.1

package retirement

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestDependencyChangeIndexColdRestartPreservesExactCutAndRefusal(t *testing.T) {
	const tenant = "a1000000-0000-4000-8000-000000000001"
	const otherTenant = "b2000000-0000-4000-8000-000000000002"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := events.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	appendDependency := func(payload depstate.Payload) events.Event {
		t.Helper()
		ev, err := depstate.Encode(payload)
		if err != nil {
			t.Fatal(err)
		}
		got, err := log.Append(t.Context(), ev)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	dependent := depstate.Dependent{Class: depstate.DependentCredential, ID: "leaf-1"}
	first := appendDependency(depstate.DependencyRegisteredV1{
		TenantID: tenant, KeyID: "key-a", Dependent: dependent, Origin: depstate.RegistrationOriginIssued,
	})
	if _, err := log.Append(t.Context(), events.Event{Type: "test.unrelated", TenantID: tenant, Data: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	appendDependency(depstate.DependencyReleasedV1{TenantID: tenant, KeyID: "key-b", Dependent: dependent})
	appendDependency(depstate.DependencyReleasedV1{TenantID: otherTenant, KeyID: "key-a", Dependent: dependent})
	matching := appendDependency(depstate.DependencyReleasedV1{TenantID: tenant, KeyID: "key-a", Dependent: dependent})
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = events.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	coordinator := &Coordinator{log: log}
	changed, err := coordinator.dependencyChangedBetween(t.Context(), tenant, "key-a", first.Sequence+1, matching.Sequence-1)
	if err != nil || changed {
		t.Fatalf("unrelated prefix changed key-a: changed=%t err=%v", changed, err)
	}
	changed, err = coordinator.dependencyChangedBetween(t.Context(), tenant, "key-a", first.Sequence+1, matching.Sequence)
	if err != nil || !changed {
		t.Fatalf("exact completion cut missed key-a: changed=%t err=%v", changed, err)
	}
	if _, err := log.Append(t.Context(), events.Event{Type: depstate.TypeDependencyReleased, TenantID: tenant, Data: []byte(`{"tenant_id":`)}); err != nil {
		t.Fatal(err)
	}
	head, err := log.LastSequence(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.dependencyChangedBetween(t.Context(), tenant, "key-a", matching.Sequence+1, head); err == nil {
		t.Fatal("malformed retained dependency event was ignored")
	}
	leaf, err := json.Marshal(projections.CAEndEntityInventoried{ID: "issued-leaf-2", CAID: "key-a", Serial: "99"})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := log.Append(t.Context(), events.Event{
		Type: projections.EventCAEndEntityIssued, TenantID: tenant,
		SchemaVersion: projections.CAEndEntityInventorySchemaVersion, Data: leaf,
	})
	if err != nil {
		t.Fatal(err)
	}
	changed, err = coordinator.dependencyChangedBetween(t.Context(), tenant, "key-a", issued.Sequence, issued.Sequence)
	if err != nil || !changed {
		t.Fatalf("late CA issuance escaped frozen retirement cut: changed=%t err=%v", changed, err)
	}
}
