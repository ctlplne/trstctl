// SPDX-License-Identifier: MPL-2.0

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/store"
)

// This test used to assert that all seven declared source kinds were advertised
// on every enrolled agent — which is exactly the defect the gap analysis found
// (truth-integrity 1). The agent binary constructs enumerators for four of them.
// Asserting the other three were advertised made the over-advertisement look
// deliberate and kept it green.
//
// It now asserts the honest contract in both directions: what is advertised is
// what the agent binary can collect, and the kinds with no enumerator are absent.
// docs/agent_advertised_capability_test.go independently proves each advertised
// kind has a constructor the agent binary actually calls.

func TestAgentResponseAdvertisesOnlyShippedDiscoveryCapabilities(t *testing.T) {
	got := toAgentResponse(store.Agent{
		ID:     "11111111-1111-1111-1111-111111111111",
		Name:   "edge-01",
		Status: "online",
	})
	if got.InventoryReportPath != "agent.mtls.ReportInventory" {
		t.Fatalf("inventory report path = %q, want served mTLS ReportInventory", got.InventoryReportPath)
	}

	want := map[string]bool{}
	for _, s := range discovery.ShippedSourceKinds() {
		want[s.Kind] = false
	}
	if len(want) == 0 {
		t.Fatal("no shipped source kinds declared; the agent collects something")
	}

	for _, capability := range got.DiscoveryCapabilities {
		seen, ok := want[capability.SourceKind]
		if !ok {
			t.Fatalf("agent advertises %q, which the agent binary does not ship an enumerator for: %+v",
				capability.SourceKind, capability)
		}
		if seen {
			t.Fatalf("duplicate endpoint discovery capability for %s", capability.SourceKind)
		}
		if capability.ReportedOver != "agent.mtls.ReportInventory" || !capability.MetadataOnly || capability.PrivateKeyBytes {
			t.Fatalf("unsafe or unrouted endpoint discovery capability: %+v", capability)
		}
		if capability.Label == "" {
			t.Fatalf("capability %q has no operator-facing label", capability.SourceKind)
		}
		want[capability.SourceKind] = true
	}
	for source, seen := range want {
		if !seen {
			t.Fatalf("shipped source %q is collected by the agent but not advertised: %+v", source, got.DiscoveryCapabilities)
		}
	}
}

// TestAgentResponseDoesNotAdvertiseUnbuiltEnumerators pins the specific three the
// gap analysis found. Each returns to the advertised set only when its enumerator
// is genuinely wired into the agent binary.
func TestAgentResponseDoesNotAdvertiseUnbuiltEnumerators(t *testing.T) {
	got := toAgentResponse(store.Agent{ID: "22222222-2222-2222-2222-222222222222", Name: "edge-02", Status: "online"})
	advertised := map[string]struct{}{}
	for _, capability := range got.DiscoveryCapabilities {
		advertised[capability.SourceKind] = struct{}{}
	}
	for _, kind := range []string{"pkcs11", "windows-store", "k8s-secret"} {
		if _, ok := advertised[kind]; ok {
			t.Errorf("agent advertises %q; if its enumerator now ships, add it to discovery.ShippedSourceKinds and drop it from this list in the same change", kind)
		}
	}
}

// TestAdvertisedCapabilitiesNameTheirEnableFlags keeps the panel from reading as
// coverage that is running. Every shipped source here is opt-in: it collects
// nothing until an operator points it at roots, so the flags travel with the
// capability.
func TestAdvertisedCapabilitiesNameTheirEnableFlags(t *testing.T) {
	got := toAgentResponse(store.Agent{ID: "33333333-3333-3333-3333-333333333333", Name: "edge-03", Status: "online"})
	for _, capability := range got.DiscoveryCapabilities {
		if len(capability.EnableFlags) == 0 {
			t.Errorf("capability %q lists no enable flags; if it is always-on, say so explicitly in ShippedSourceKinds rather than leaving the field empty",
				capability.SourceKind)
		}
	}
}
