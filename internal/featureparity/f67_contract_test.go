// SPDX-License-Identifier: BUSL-1.1

package featureparity

import (
	"slices"
	"testing"
)

func TestF67PKISecretContractRequiresPreviewBoundConfigurationJourney(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	item, ok := featureByID(catalog, "F67")
	if !ok {
		t.Fatal("F67 missing from canonical catalog")
	}
	if item.Contract.ReleaseBlocking || item.Contract.Maturity != MaturityCompleteVerticalSlice {
		t.Fatalf("F67 contract = release_blocking=%t maturity=%q, want false/%q",
			item.Contract.ReleaseBlocking, item.Contract.Maturity, MaturityCompleteVerticalSlice)
	}
	for stage, record := range map[string]StageRecord{
		"configure": item.Contract.Stages.Configure,
		"preview":   item.Contract.Stages.Preview,
	} {
		if record.Status != StageComplete {
			t.Errorf("F67 %s status = %q, want complete", stage, record.Status)
		}
	}
	for _, ref := range []string{
		"internal/api/pki_secret_preview.go",
		"internal/server/pki_secret_preview_served_test.go",
		"web/src/pages/secrets/PKISecretWorkflow.tsx",
		"web/src/__tests__/secrets.test.tsx",
	} {
		if !slices.Contains(item.Contract.Stages.Configure.Evidence, ref) &&
			!slices.Contains(item.Contract.Stages.Preview.Evidence, ref) {
			t.Errorf("F67 configure/preview evidence missing %q", ref)
		}
	}
	if !slices.Contains(item.APISurface, "previewPKISecret") || !slices.Contains(item.CLISurface, "secrets pki preview") {
		t.Fatal("F67 effect-free preview API or CLI is not linked to the capability")
	}

	// A green label is not enough: removing preview must make the oracle reject
	// the row and compute it as incomplete.
	item.Contract.Stages.Preview = StageRecord{Status: StageMissing, Reason: "negative control: preview deliberately removed"}
	if err := ValidateCapabilityContract(item); err == nil {
		t.Fatal("negative parity oracle accepted F67 with preview deliberately removed")
	}
	if ComputeMaturity(item.Contract.Stages) == MaturityCompleteVerticalSlice {
		t.Fatal("negative parity oracle called F67 complete without preview")
	}
}
