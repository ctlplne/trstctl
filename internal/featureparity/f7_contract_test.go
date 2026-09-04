// SPDX-License-Identifier: MPL-2.0

package featureparity

import (
	"strings"
	"testing"
)

func TestDeploymentConnectorsAreACompleteReviewFirstVerticalSlice(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	var f7 *Item
	for i := range catalog.Items {
		if catalog.Items[i].FeatureID == "F7" {
			f7 = &catalog.Items[i]
			break
		}
	}
	if f7 == nil {
		t.Fatal("F7 deployment connectors row is missing")
	}

	contract := f7.Contract
	if contract.Tool != ToolOperations {
		t.Fatalf("F7 tool = %q, want %q", contract.Tool, ToolOperations)
	}
	if contract.Maturity != MaturityCompleteVerticalSlice || contract.ReleaseBlocking {
		t.Fatalf("F7 maturity/release_blocking = %q/%t, want complete_vertical_slice/false", contract.Maturity, contract.ReleaseBlocking)
	}
	for name, stage := range map[string]StageRecord{
		"discover":   contract.Stages.Discover,
		"understand": contract.Stages.Understand,
		"configure":  contract.Stages.Configure,
		"preview":    contract.Stages.Preview,
		"execute":    contract.Stages.Execute,
		"observe":    contract.Stages.Observe,
		"recover":    contract.Stages.Recover,
		"verify":     contract.Stages.Verify,
		"automate":   contract.Stages.Automate,
	} {
		if stage.Status != StageComplete || len(stage.Evidence) == 0 {
			t.Errorf("F7 %s stage = %q with %d evidence items, want complete with evidence", name, stage.Status, len(stage.Evidence))
		}
	}

	for _, want := range []string{"testConnectorTarget", "deployConnectorTarget", "rollbackConnectorTarget"} {
		if !containsExactString(f7.APISurface, want) {
			t.Errorf("F7 api_surface is missing %q", want)
		}
	}
	for _, want := range []string{"connector target test", "connector target deploy", "connector target rollback"} {
		if !containsExactString(f7.CLISurface, want) {
			t.Errorf("F7 cli_surface is missing %q", want)
		}
	}

	preview := strings.ToLower(strings.Join(contract.Stages.Preview.Evidence, "\n"))
	for _, want := range []string{"target-vantage", "zero", "testconnectortarget", "connector target test"} {
		if !strings.Contains(preview, want) {
			t.Errorf("F7 preview evidence must mention %q, got %q", want, preview)
		}
	}
	recovery := strings.ToLower(strings.Join(contract.Stages.Recover.Evidence, "\n"))
	for _, want := range []string{"rollbackconnectortarget", "connector target rollback", "predecessor", "independent tls"} {
		if !strings.Contains(recovery, want) {
			t.Errorf("F7 recovery evidence must mention %q, got %q", want, recovery)
		}
	}
}
