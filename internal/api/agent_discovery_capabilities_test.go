// SPDX-License-Identifier: MPL-2.0

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/store"
)

func TestAgentResponseAdvertisesEndpointDiscoveryCapabilitiesCAPDISC02(t *testing.T) {
	got := toAgentResponse(store.Agent{
		ID:     "11111111-1111-1111-1111-111111111111",
		Name:   "edge-01",
		Status: "online",
	})
	if got.InventoryReportPath != "agent.mtls.ReportInventory" {
		t.Fatalf("inventory report path = %q, want served mTLS ReportInventory", got.InventoryReportPath)
	}
	wantSources := map[string]bool{
		"filesystem":    false,
		"pkcs11":        false,
		"windows-store": false,
		"k8s-secret":    false,
		"trust-store":   false,
		"private-key":   false,
	}
	for _, cap := range got.DiscoveryCapabilities {
		seen, ok := wantSources[cap.SourceKind]
		if !ok {
			t.Fatalf("unexpected endpoint discovery capability: %+v", cap)
		}
		if seen {
			t.Fatalf("duplicate endpoint discovery capability for %s", cap.SourceKind)
		}
		if cap.ReportedOver != "agent.mtls.ReportInventory" || !cap.MetadataOnly || cap.PrivateKeyBytes {
			t.Fatalf("unsafe or unrouted endpoint discovery capability: %+v", cap)
		}
		wantSources[cap.SourceKind] = true
	}
	for source, seen := range wantSources {
		if !seen {
			t.Fatalf("missing endpoint discovery capability %q in %+v", source, got.DiscoveryCapabilities)
		}
	}
}
