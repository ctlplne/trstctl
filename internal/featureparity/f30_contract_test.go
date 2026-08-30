// SPDX-License-Identifier: MPL-2.0

package featureparity

import (
	"slices"
	"testing"
)

func TestF30AttestedIssuanceContractRequiresExactPreviewAndRetryEvidence(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	item, ok := featureByID(catalog, "F30")
	if !ok {
		t.Fatal("F30 missing from canonical catalog")
	}
	if item.Contract.ReleaseBlocking || item.Contract.Maturity != MaturityCompleteVerticalSlice || item.Contract.Stages.Preview.Status != StageComplete {
		t.Fatalf("F30 is not a complete preview-bound workflow: %+v", item.Contract)
	}
	for _, ref := range []string{
		"internal/api/attested_issuance.go",
		"internal/server/attested_issuance_served_test.go",
		"web/src/pages/workloads/AttestedSVIDWorkflow.tsx",
		"web/src/__tests__/attested_svid_workflow.test.tsx",
	} {
		if !slices.Contains(item.Contract.Stages.Preview.Evidence, ref) {
			t.Errorf("F30 preview lacks exact implementation/control evidence %q", ref)
		}
	}
	if !slices.Contains(item.APISurface, "previewAttestedSVID") || !slices.Contains(item.CLISurface, "workloads attested-issuance preview") {
		t.Fatal("F30 preview API or read-only CLI is not linked to the capability")
	}
	// Deliberately remove the review stage without changing the green label. The
	// oracle must reject the false-complete contract instead of printing green.
	item.Contract.Stages.Preview = StageRecord{Status: StageMissing, Reason: "negative control: preview deliberately removed"}
	if err := ValidateCapabilityContract(item); err == nil {
		t.Fatal("negative parity oracle accepted F30 with its preview deliberately removed")
	}
	if ComputeMaturity(item.Contract.Stages) == MaturityCompleteVerticalSlice {
		t.Fatal("negative parity oracle called a missing-preview workflow complete")
	}
}
