// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/store"
)

// A Kubernetes TLS resource a run found and could not deliver to is recorded
// as not_delivered with its reason (owner decision 2026-10-25, B15-L1). The
// status belongs to that kind alone and never travels without a reason.
func TestDiscoveryTargetResultsAcceptNotDeliveredOnlyForKubernetesTLSWithAReason(t *testing.T) {
	ok := []store.DiscoveryTargetResult{
		{Kind: "k8s_tls_auto_issuance", Target: "Ingress:payments/web", Status: "not_delivered", Error: "in-cluster agent mode is not built"},
		{Kind: "network", Target: "10.0.0.5:443", Status: "succeeded"},
	}
	if err := validateDiscoveryTargetResults(ok); err != nil {
		t.Fatalf("valid outcomes refused: %v", err)
	}
	for name, bad := range map[string]store.DiscoveryTargetResult{
		"not_delivered on a network target": {Kind: "network", Target: "10.0.0.6:443", Status: "not_delivered", Error: "x"},
		"not_delivered without a reason":    {Kind: "k8s_tls_auto_issuance", Target: "Gateway:edge/gw", Status: "not_delivered"},
		"an unknown kind":                   {Kind: "k8s", Target: "Ingress:a/b", Status: "failed", Error: "x"},
	} {
		if err := validateDiscoveryTargetResults([]store.DiscoveryTargetResult{bad}); err == nil || !strings.Contains(err.Error(), "discovery target result") {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}
