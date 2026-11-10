// SPDX-License-Identifier: BUSL-1.1

package issuancerequest

import (
	"errors"
	"testing"
)

// A225-L1: two sets of identifiers name one person when any non-empty one
// matches, ignoring case and surrounding space.
func TestSameIdentityMatchesAcrossIdentifiersA225L1(t *testing.T) {
	for _, tc := range []struct {
		requester, approver []string
		same                bool
	}{
		{[]string{"Alice.Ng@corp.example"}, []string{"oidc|1", " alice.ng@corp.example ", "Alice Ng"}, true},
		{[]string{"alice ng"}, []string{"oidc|1", "alice.ng@corp.example", "Alice Ng"}, true},
		{[]string{"oidc|1", "", ""}, []string{"OIDC|1"}, true},
		{[]string{"jira:NHI-1"}, []string{"oidc|1", "alice.ng@corp.example", "Alice Ng"}, false},
		{[]string{"", "  "}, []string{"", "x"}, false},
	} {
		if got := SameIdentity(tc.requester, tc.approver); got != tc.same {
			t.Errorf("SameIdentity(%q, %q) = %v, want %v", tc.requester, tc.approver, got, tc.same)
		}
	}
	if err := CanDecide("Dana@Example.test", "dana@example.test"); !errors.Is(err, ErrRequesterCannotDecide) {
		t.Fatalf("CanDecide with the requester's subject in another case = %v, want the separation-of-duties refusal", err)
	}
}
