// SPDX-License-Identifier: MPL-2.0

package featureparity

import (
	"slices"
	"testing"
)

// F33 is not complete because an approvals route exists. It is complete only
// when the requester can preview the exact request, a different principal can
// review it, failed issuance can be retried without minting under a new
// identity, and the console binds those stages into one understandable journey.
func TestF33JITApprovalContractClosesPreviewAndRecovery(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	var f33 *Item
	for i := range catalog.Items {
		if catalog.Items[i].FeatureID == "F33" {
			f33 = &catalog.Items[i]
			break
		}
	}
	if f33 == nil {
		t.Fatal("F33 missing from canonical catalog")
	}
	if f33.Contract.ReleaseBlocking || f33.Contract.Maturity != MaturityCompleteVerticalSlice {
		t.Fatalf("F33 contract = release_blocking=%t maturity=%q, want false/%q",
			f33.Contract.ReleaseBlocking, f33.Contract.Maturity, MaturityCompleteVerticalSlice)
	}
	for stage, record := range map[string]StageRecord{
		"preview": f33.Contract.Stages.Preview,
		"recover": f33.Contract.Stages.Recover,
	} {
		if record.Status != StageComplete {
			t.Errorf("F33 %s status = %q, want complete", stage, record.Status)
		}
	}
	for _, evidence := range []string{
		"internal/server/issuance_request_served_test.go",
		"web/src/pages/RequestCredential.tsx",
		"web/src/pages/Approvals.tsx",
		"web/src/components/IssuanceRequestsPanel.tsx",
	} {
		if !slices.Contains(f33.Contract.Stages.Preview.Evidence, evidence) &&
			!slices.Contains(f33.Contract.Stages.Recover.Evidence, evidence) &&
			!slices.Contains(f33.Contract.Stages.Execute.Evidence, evidence) {
			t.Errorf("F33 exact journey evidence missing %q", evidence)
		}
	}
}
