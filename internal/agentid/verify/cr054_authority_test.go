// SPDX-License-Identifier: BUSL-1.1

package verify

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/agentid/delegation/carriage"
	"trstctl.com/trstctl/internal/crypto"
)

func TestCR054RelyingPartyIntersectsSignedHeadAuthority(t *testing.T) {
	repr := buildRepr(t, "cr054-prompt", []string{"search", "shell.exec"})
	bound := fullBinding(repr, "reader", nil)
	bound.ChainHeadDigest = crypto.SHA256Sum([]byte("verified-head"))
	bound.ComparatorVersion = "agid.authority.compare/v2"
	bound.VerifiedHeadScopes = []string{"read-object"}
	bound.VerifiedHeadTools = []string{"search"}
	bound.VerifiedHeadAuthorityClasses = []string{"reader"}
	clk := FixedClock(unixToTime(testNow))

	for _, tc := range []struct {
		name                   string
		bound                  carriage.BoundValues
		class, operation, tool string
		want                   error
	}{
		{name: "signed subset", bound: bound, class: "reader", operation: "read-object", tool: "search"},
		{name: "operation outside head", bound: bound, class: "reader", operation: "write-object", tool: "search", want: ErrActionExceedsAuthority},
		{name: "tool outside head", bound: bound, class: "reader", operation: "read-object", tool: "shell.exec", want: ErrToolExceedsChainAuthority},
		{name: "class outside head", bound: func() carriage.BoundValues { b := bound.Clone(); b.DesignatedClass = "tenant-admin"; return b }(), class: "tenant-admin", operation: "read-object", tool: "search", want: ErrAuthorityClassNotPermitted},
		{name: "legacy unbound head", bound: func() carriage.BoundValues {
			b := bound.Clone()
			b.ComparatorVersion = "agid.authority.compare/v1"
			b.VerifiedHeadScopes = nil
			b.VerifiedHeadTools = nil
			b.VerifiedHeadAuthorityClasses = nil
			return b
		}(), class: "reader", operation: "read-object", tool: "search", want: ErrChainAuthorityUnbound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred, root := tokenCred(t, tc.bound, testNow-60, testNow+60)
			policy := approvePolicy(repr, tc.class, tc.operation, []string{"search", "shell.exec"})
			_, err := Verify(cred, root, policy, Action{Operation: tc.operation, Tool: tc.tool}, clk)
			if tc.want == nil && err != nil {
				t.Fatalf("signed subset refused: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}
