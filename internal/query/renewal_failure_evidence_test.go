// SPDX-License-Identifier: BUSL-1.1

package query

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/events"
)

func TestRenewalFailureReasonOnlyExposesRedactedAllowlistedCause(t *testing.T) {
	const secret = "-----BEGIN PRIVATE KEY-----a_fake_key-----END PRIVATE KEY-----"
	data := []byte(`{"reason":"CA refused request ` + secret + `"}`)
	if got := renewalFailureReason(events.Event{Type: "certificate.recorded", Data: data}); got != "" {
		t.Fatalf("nonfailure event exposed reason: %q", got)
	}
	if got := renewalFailureReason(events.Event{Type: "identity.renewal_failed", Data: data}); !strings.Contains(got, "CA refused request") || strings.Contains(got, "BEGIN PRIVATE KEY") {
		t.Fatalf("renewal reason was lost or key material survived: %q", got)
	}
	if got := renewalFailureReason(events.Event{Type: "identity.renewal_failed", Data: []byte(`{not-json`)}); got != "" {
		t.Fatalf("malformed failure event exposed reason: %q", got)
	}
}
