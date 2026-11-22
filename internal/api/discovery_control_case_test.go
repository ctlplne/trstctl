// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/discovery/sourcecatalog"
)

func TestCR049DiscoveryControlFieldsUseExactKeysAcrossSourceKinds(t *testing.T) {
	for _, tt := range []struct {
		name string
		raw  string
		ok   bool
	}{
		{"canonical nested controls", `{"providers":[{"token_ref":"env:APPROVED","allow_private_endpoint":true,"private_egress_cidrs":["10.0.0.0/8"],"endpoint":"https://example.com"}]}`, true},
		{"case-folded reference", `{"providers":[{"Token_Ref":"env:SECRET"}]}`, false},
		{"case-folded egress grant", `{"providers":[{"Allow_Private_Endpoint":true}]}`, false},
		{"case-folded destination", `{"providers":[{"Endpoint":"https://example.com"}]}`, false},
		{"duplicate reference", `{"providers":[{"token_ref":"env:A","token_ref":"env:B"}]}`, false},
		{"other case-sensitive metadata", `{"observations":[{"AWS:TokenIssueTime":"2026-11-22T00:00:00Z"}]}`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := sourcecatalog.ValidateControlFieldCase([]byte(tt.raw))
			if (err == nil) != tt.ok {
				t.Fatalf("case check error = %v, want success %v", err, tt.ok)
			}
		})
	}
}
