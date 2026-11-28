// SPDX-License-Identifier: BUSL-1.1

package server

import "testing"

func TestRevocationPublisherUsesUsableReasonForRetainedIntent(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"", "unspecified"},
		{"removeFromCRL", "unspecified"},
		{"keyCompromise", "keyCompromise"},
	} {
		got, err := publicationRevocationReason(tc.input)
		if err != nil || got != tc.want {
			t.Fatalf("publication reason %q = %q, %v; want %q", tc.input, got, err, tc.want)
		}
	}
	if _, err := publicationRevocationReason("unknown"); err == nil {
		t.Fatal("unknown publication reason was accepted")
	}
}
