// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TestSecretStoreKindRoutesThroughServedSecretManagerConnectors pins A0.2b:
// a secret_store source no longer dead-ends in the "no server-side connector"
// fallback — it dispatches through the same served secret-manager connector
// factory as cloud_secret, so a served backend runs and an unserved provider
// fails with the connector's specific error.
func TestSecretStoreKindRoutesThroughServedSecretManagerConnectors(t *testing.T) {
	d := &issuanceDispatcher{}
	ctx := context.Background()

	// An unserved provider reaches the connector factory and gets its clear
	// refusal — proof the kind routed to the executor, not the fallback.
	src := store.DiscoverySource{ID: "src-1", TenantID: "t-1", Kind: "secret_store",
		Config: []byte(`{"providers":[{"provider":"infisical"}]}`)}
	_, status, msg, err := d.executeDiscoveryRun(ctx, "t-1", src, projections.DiscoveryRunQueued{ID: "run-1"})
	if err != nil {
		t.Fatalf("executeDiscoveryRun: %v", err)
	}
	if status != "failed" || !strings.Contains(msg, `unsupported cloud secret-manager provider "infisical"`) {
		t.Fatalf("status=%q msg=%q, want the connector's unsupported-provider refusal, not the no-connector fallback", status, msg)
	}

	// An empty provider list fails with a kind-aware message.
	src.Config = []byte(`{"providers":[]}`)
	_, status, msg, err = d.executeDiscoveryRun(ctx, "t-1", src, projections.DiscoveryRunQueued{ID: "run-2"})
	if err != nil {
		t.Fatalf("executeDiscoveryRun: %v", err)
	}
	if status != "failed" || !strings.Contains(msg, "secret_store discovery requires at least one provider") {
		t.Fatalf("status=%q msg=%q, want the kind-aware empty-provider refusal", status, msg)
	}

	// cloud_secret keeps identical behavior through the shared path.
	src.Kind = "cloud_secret"
	_, status, msg, err = d.executeDiscoveryRun(ctx, "t-1", src, projections.DiscoveryRunQueued{ID: "run-3"})
	if err != nil {
		t.Fatalf("executeDiscoveryRun: %v", err)
	}
	if status != "failed" || !strings.Contains(msg, "cloud_secret discovery requires at least one provider") {
		t.Fatalf("status=%q msg=%q, want cloud_secret's own kind in the message", status, msg)
	}
}
