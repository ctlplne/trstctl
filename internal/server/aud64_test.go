// SPDX-License-Identifier: MPL-2.0

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
)

func TestAUD64ServiceDependencyInventoryContract(t *testing.T) {
	t.Parallel()
	valid := transport.InventoryFinding{
		Kind: agentServiceDependencyFindingKind,
		Ref:  "lb-edge",
		Metadata: map[string]string{
			"workload": "checkout-service",
			"target":   "lb-edge",
			"protocol": "https",
		},
	}
	if err := validateAgentServiceDependencyFinding(agentServiceDependencyFindingKind, valid); err != nil {
		t.Fatalf("valid service dependency: %v", err)
	}
	padded := valid
	padded.Kind = " service_dependency "
	if err := validateAgentServiceDependencyFinding(" service_dependency ", padded); err != nil {
		t.Fatalf("normalized service dependency: %v", err)
	}

	for name, test := range map[string]struct {
		source  string
		finding transport.InventoryFinding
	}{
		"finding without source contract": {source: "host", finding: valid},
		"source without finding contract": {
			source:  agentServiceDependencyFindingKind,
			finding: transport.InventoryFinding{Kind: "certificate", Ref: "lb-edge", Metadata: valid.Metadata},
		},
		"missing workload": {
			source:  agentServiceDependencyFindingKind,
			finding: transport.InventoryFinding{Kind: agentServiceDependencyFindingKind, Ref: "lb-edge", Metadata: map[string]string{"target": "lb-edge"}},
		},
		"missing target": {
			source:  agentServiceDependencyFindingKind,
			finding: transport.InventoryFinding{Kind: agentServiceDependencyFindingKind, Ref: "lb-edge", Metadata: map[string]string{"workload": "checkout-service"}},
		},
		"ambiguous target": {
			source: agentServiceDependencyFindingKind,
			finding: transport.InventoryFinding{
				Kind: agentServiceDependencyFindingKind, Ref: "lb-edge",
				Metadata: map[string]string{"workload": "checkout-service", "target": "other-edge"},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := validateAgentServiceDependencyFinding(test.source, test.finding); err == nil {
				t.Fatal("invalid service dependency was accepted")
			}
		})
	}

	ordinary := transport.InventoryFinding{Kind: "certificate", Ref: "host-a"}
	if err := validateAgentServiceDependencyFinding("host", ordinary); err != nil {
		t.Fatalf("ordinary inventory was changed by AUD-64 validation: %v", err)
	}
}
