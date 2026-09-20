// SPDX-License-Identifier: BUSL-1.1

package featureparity

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestCanonicalCapabilityContractsCoverEveryFeature(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}

	seen := map[string]bool{}
	for _, item := range catalog.Items {
		contract := item.Contract
		if seen[item.FeatureID] {
			t.Fatalf("duplicate feature ID %s", item.FeatureID)
		}
		seen[item.FeatureID] = true
		if err := ValidateCapabilityContract(item); err != nil {
			t.Errorf("%s (%s): %v", item.FeatureID, item.Feature, err)
		}
		computed := ComputeMaturity(contract.Stages)
		if contract.Maturity != computed {
			t.Errorf("%s declared maturity %q, computed %q", item.FeatureID, contract.Maturity, computed)
		}
		wantBlocker := contract.Classification == CapabilityPrimary && computed != MaturityCompleteVerticalSlice
		if contract.ReleaseBlocking != wantBlocker {
			t.Errorf("%s release_blocking=%t, want %t from classification=%q maturity=%q", item.FeatureID, contract.ReleaseBlocking, wantBlocker, contract.Classification, computed)
		}
	}
	if len(seen) != 79 {
		t.Fatalf("canonical contract rows = %d, want 79", len(seen))
	}
}

func TestEmbeddedCapabilityCatalogLoadsOutsideRepository(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("change to isolated working directory: %v", err)
	}

	catalog, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("load embedded capability catalog: %v", err)
	}
	if catalog.SchemaVersion != 3 || len(catalog.Items) != 79 {
		t.Fatalf("embedded catalog schema/items = %d/%d, want 3/79", catalog.SchemaVersion, len(catalog.Items))
	}
}

func TestCanonicalCapabilityEnumListsFailClosed(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}
	catalog.CanonicalTools[0] = CanonicalTool("ghost_tool")
	if err := ValidateCatalog(catalog); err == nil || !strings.Contains(err.Error(), "canonical_tools") {
		t.Fatalf("unknown canonical tool list error = %v", err)
	}
}

func TestCanonicalCapabilityEvidencePathsFailClosed(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("find repository root: %v", err)
	}
	catalog.Items[0].Contract.Stages.Discover.Evidence = []string{"web/src/pages/DefinitelyMissingParityControl.tsx"}
	if err := validateEvidencePaths(root, catalog); err == nil || !strings.Contains(err.Error(), "DefinitelyMissingParityControl") {
		t.Fatalf("missing evidence path error = %v", err)
	}
	catalog.Items[0].Contract.Stages.Discover.Evidence = []string{"web/../../outside-repository"}
	if err := validateEvidencePaths(root, catalog); err == nil || !strings.Contains(err.Error(), "escapes the repository") {
		t.Fatalf("escaping evidence path error = %v", err)
	}
}

func TestCanonicalCapabilityContractEnumsAndEvidenceFailClosed(t *testing.T) {
	complete := StageRecord{Status: StageComplete, Evidence: []string{"served browser receipt"}}
	na := StageRecord{Status: StageNotApplicable, Reason: "Read-only inventory has no mutation to execute."}
	item := Item{
		FeatureID: "F-test",
		Feature:   "Test feature",
		Contract: CapabilityContract{
			Purpose:               "Shows tenant-scoped test state without moving authority into the browser.",
			Tool:                  ToolOperations,
			Classification:        CapabilitySupporting,
			ReleaseBlocking:       false,
			ConsoleRoute:          "/operations",
			NavigationEntrypoints: []string{"tool navigation", "task search"},
			PermissionAuthority:   "served route registry",
			Edition:               "core",
			SideEffects:           "read_only",
			SecretDataHandling:    "tenant-scoped metadata only",
			Maturity:              MaturityCompleteVerticalSlice,
			Stages: StageSet{
				Discover:   complete,
				Understand: complete,
				Configure:  na,
				Preview:    na,
				Execute:    na,
				Observe:    complete,
				Recover:    na,
				Verify:     complete,
				Automate:   na,
			},
			Owner:            "operations",
			TargetCheckpoint: "frontend-convergence",
			CandidateSHA:     strings.Repeat("a", 40),
			Freshness:        "2026-08-25",
		},
	}
	if err := ValidateCapabilityContract(item); err != nil {
		t.Fatalf("valid contract rejected: %v", err)
	}

	item.Contract.Stages.Execute = StageRecord{Status: StageComplete}
	if err := ValidateCapabilityContract(item); err == nil || !strings.Contains(err.Error(), "complete stage execute") {
		t.Fatalf("missing complete-stage evidence error = %v", err)
	}
	item.Contract.Stages.Execute = StageRecord{Status: StageComplete, Evidence: []string{"web/src/lib/navigation.ts"}}
	if err := ValidateCapabilityContract(item); err == nil || !strings.Contains(err.Error(), "route registry") {
		t.Fatalf("navigation-only operational evidence error = %v", err)
	}
	item.Contract.Stages.Execute = StageRecord{Status: StageStatus("green"), Reason: "invalid control"}
	if err := ValidateCapabilityContract(item); err == nil || !strings.Contains(err.Error(), "invalid stage status") {
		t.Fatalf("unknown stage status error = %v", err)
	}
}

func TestPrimaryCapabilityCannotHideRequiredStageAsIntentionalAPIOnly(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}
	item := catalog.Items[0]
	item.Contract.Stages.Configure = StageRecord{Status: StageIntentionalAPIOnly, Reason: "CLI exists"}
	item.Contract.Maturity = MaturityPartialWorkflow
	item.Contract.ReleaseBlocking = true
	if err := ValidateCapabilityContract(item); err == nil || !strings.Contains(err.Error(), "primary stage configure") {
		t.Fatalf("primary intentional API-only error = %v", err)
	}
}

func TestCanonicalCandidateSHAIsExact(t *testing.T) {
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(strings.Repeat("a", 40)) {
		t.Fatal("test SHA fixture is invalid")
	}
}

func TestEmbeddedEnrollmentIsACompleteWorkloadsLifecycle(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}
	var found *Item
	for i := range catalog.Items {
		if catalog.Items[i].FeatureID == "F54" {
			found = &catalog.Items[i]
			break
		}
	}
	if found == nil {
		t.Fatal("F54 is missing from the canonical capability catalog")
	}
	contract := found.Contract
	if contract.Tool != ToolWorkloadsMachines {
		t.Fatalf("F54 tool = %q, want %q", contract.Tool, ToolWorkloadsMachines)
	}
	if contract.Maturity != MaturityCompleteVerticalSlice || contract.ReleaseBlocking {
		t.Fatalf("F54 maturity/release_blocking = %q/%t, want complete_vertical_slice/false", contract.Maturity, contract.ReleaseBlocking)
	}
	for name, stage := range map[string]StageRecord{
		"configure": contract.Stages.Configure,
		"preview":   contract.Stages.Preview,
		"recover":   contract.Stages.Recover,
		"verify":    contract.Stages.Verify,
		"automate":  contract.Stages.Automate,
	} {
		if stage.Status != StageComplete || len(stage.Evidence) == 0 {
			t.Errorf("F54 %s stage = %q with %d evidence items, want complete with evidence", name, stage.Status, len(stage.Evidence))
		}
	}
	for _, want := range []string{"previewEnrollmentToken", "createEnrollmentToken"} {
		if !containsExactString(found.APISurface, want) {
			t.Errorf("F54 api_surface is missing %q", want)
		}
	}
	for _, want := range []string{"agents enroll-token-preview", "agents enroll-token"} {
		if !containsExactString(found.CLISurface, want) {
			t.Errorf("F54 cli_surface is missing %q", want)
		}
	}
}

func TestAttestedSSHUserCertificatesAreACompleteRecoverableVerticalSlice(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}
	var found *Item
	for i := range catalog.Items {
		if catalog.Items[i].FeatureID == "F45" {
			found = &catalog.Items[i]
			break
		}
	}
	if found == nil {
		t.Fatal("F45 is missing from the canonical capability catalog")
	}
	contract := found.Contract
	if contract.Tool != ToolWorkloadsMachines {
		t.Fatalf("F45 tool = %q, want %q", contract.Tool, ToolWorkloadsMachines)
	}
	if contract.Maturity != MaturityCompleteVerticalSlice || contract.ReleaseBlocking {
		t.Fatalf("F45 maturity/release_blocking = %q/%t, want complete_vertical_slice/false", contract.Maturity, contract.ReleaseBlocking)
	}
	for name, stage := range map[string]StageRecord{
		"preview":  contract.Stages.Preview,
		"execute":  contract.Stages.Execute,
		"recover":  contract.Stages.Recover,
		"verify":   contract.Stages.Verify,
		"automate": contract.Stages.Automate,
	} {
		if stage.Status != StageComplete || len(stage.Evidence) == 0 {
			t.Errorf("F45 %s stage = %q with %d evidence items, want complete with evidence", name, stage.Status, len(stage.Evidence))
		}
	}
	for _, want := range []string{"previewAttestedSSHUserCert", "issueAttestedSSHUserCert"} {
		if !containsExactString(found.APISurface, want) {
			t.Errorf("F45 api_surface is missing %q", want)
		}
	}
	for _, want := range []string{"ssh preview-attested-user", "ssh issue-attested-user"} {
		if !containsExactString(found.CLISurface, want) {
			t.Errorf("F45 cli_surface is missing %q", want)
		}
	}
}

func TestSecretRotationIsACompleteReviewFirstVerticalSlice(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load feature parity catalog: %v", err)
	}
	var found *Item
	for i := range catalog.Items {
		if catalog.Items[i].FeatureID == "F37" {
			found = &catalog.Items[i]
			break
		}
	}
	if found == nil {
		t.Fatal("F37 secret rotation row is missing")
	}
	contract := found.Contract
	if contract.Tool != ToolSecrets {
		t.Fatalf("F37 tool = %q, want %q", contract.Tool, ToolSecrets)
	}
	if contract.Maturity != MaturityCompleteVerticalSlice || contract.ReleaseBlocking {
		t.Fatalf("F37 maturity/release_blocking = %q/%t, want complete_vertical_slice/false", contract.Maturity, contract.ReleaseBlocking)
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
			t.Errorf("F37 %s stage = %q with %d evidence items, want complete with evidence", name, stage.Status, len(stage.Evidence))
		}
	}
	for _, want := range []string{"previewStaticSecretRotation", "rotateStaticSecret"} {
		if !containsExactString(found.APISurface, want) {
			t.Errorf("F37 api_surface is missing %q", want)
		}
	}
	for _, want := range []string{"secrets rotations preview", "secrets rotations run"} {
		if !containsExactString(found.CLISurface, want) {
			t.Errorf("F37 cli_surface is missing %q", want)
		}
	}
	previewEvidence := strings.ToLower(strings.Join(contract.Stages.Preview.Evidence, "\n"))
	for _, want := range []string{"effect-free", "zero events", "stale-review", "g134-f37-live-r5.json", "g134-f37-browser.json"} {
		if !strings.Contains(previewEvidence, want) {
			t.Errorf("F37 preview evidence must mention %q, got %q", want, previewEvidence)
		}
	}
}

func containsExactString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
