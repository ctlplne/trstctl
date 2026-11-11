// SPDX-License-Identifier: BUSL-1.1

package schedulerhistory

import "testing"

// A201-L1: a dynamic-lease schedule's two terminal details are members of the
// closed scheduler vocabulary for their statuses and nothing else.
func TestDynamicLeaseScheduleDetailsAreCanonicalA201L1(t *testing.T) {
	for _, c := range []struct{ status, detail string }{
		{"unsupported", DynamicLeaseProviderUnavailableError},
		{"failed", DynamicLeaseOldLeaseError},
		{"rolled_back", DynamicLeaseOldLeaseError},
	} {
		if !IsCanonicalError(c.status, c.detail) {
			t.Errorf("%s %q is not canonical", c.status, c.detail)
		}
	}
	if IsCanonicalError("failed", DynamicLeaseProviderUnavailableError) {
		t.Error("the unsupported provider detail must not stand for a failed edge")
	}
	if got := CanonicalError("unsupported", "provider said: lease engine exploded"); got != "scheduled rotation is unavailable" {
		t.Errorf("unknown unsupported detail = %q, want it collapsed", got)
	}
}
