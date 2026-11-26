// SPDX-License-Identifier: BUSL-1.1

package segmentscan_test

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/discovery/segmentscan"
)

func TestResolveRejectsCIDRProductBeforeAllocatingTargets(t *testing.T) {
	ports := make([]int, 3_000)
	for i := range ports {
		ports[i] = i + 1
	}
	raw, err := json.Marshal(map[string]any{"segment": "edge", "cidr": "192.0.2.0/30", "ports": ports})
	if err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(1, func() {
		if _, err := segmentscan.Resolve("network", raw); err == nil {
			t.Fatal("CIDR x ports exceeds the target budget")
		}
	})
	if allocs > 1_500 {
		t.Fatalf("rejecting 12,000 targets allocated %.0f objects, likely after expanding them", allocs)
	}
}

func TestResolveRejectsLargeCIDRProductWithoutMaterializingIt(t *testing.T) {
	ports := make([]int, 1_000)
	for i := range ports {
		ports[i] = i + 1
	}
	raw, err := json.Marshal(map[string]any{"segment": "edge", "cidr": "10.0.0.0/16", "ports": ports})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := segmentscan.Resolve("network", raw); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("65 million targets must be refused before allocation: %v", err)
	}
}

func TestResolveDeduplicatesPortsBeforeExpansion(t *testing.T) {
	raw := json.RawMessage(`{"segment":"edge","cidr":"192.0.2.0/30","ports":[443,443,8443,443]}`)
	got, err := segmentscan.Resolve("network", raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Targets) != 8 {
		t.Fatalf("got %d targets, want 4 addresses x 2 unique ports", len(got.Targets))
	}
}
