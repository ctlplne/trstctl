// SPDX-License-Identifier: MPL-2.0

package discovery

import "testing"

func TestValidateTriageTransition(t *testing.T) {
	allowed := []struct {
		from TriageStatus
		to   TriageStatus
	}{
		{TriageUnmanaged, TriageInvestigating},
		{TriageUnmanaged, TriageManaged},
		{TriageUnmanaged, TriageDismissed},
		{TriageInvestigating, TriageManaged},
		{TriageInvestigating, TriageDismissed},
		{TriageManaged, TriageManaged},
		{TriageDismissed, TriageDismissed},
	}
	for _, tc := range allowed {
		if err := ValidateTriageTransition(tc.from, tc.to); err != nil {
			t.Fatalf("ValidateTriageTransition(%q, %q) = %v, want nil", tc.from, tc.to, err)
		}
	}

	rejected := []struct {
		from TriageStatus
		to   TriageStatus
	}{
		{TriageManaged, TriageDismissed},
		{TriageDismissed, TriageManaged},
		{TriageDismissed, TriageInvestigating},
		{TriageUnmanaged, "unknown"},
	}
	for _, tc := range rejected {
		if err := ValidateTriageTransition(tc.from, tc.to); err == nil {
			t.Fatalf("ValidateTriageTransition(%q, %q) succeeded, want rejection", tc.from, tc.to)
		}
	}
}
