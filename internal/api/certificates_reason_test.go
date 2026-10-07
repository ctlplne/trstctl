// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"

	"trstctl.com/trstctl/internal/store"
)

func TestCertificateResponseNamesLegacyACMERevocationReason(t *testing.T) {
	legacy := store.Certificate{RevocationReason: "acme revokeCert reason code 4"}
	if got := toCertificateResponse(legacy).RevocationReason; got != "superseded" {
		t.Fatalf("legacy ACME reason = %q, want superseded", got)
	}
	custom := store.Certificate{RevocationReason: "operator incident INC-123"}
	if got := toCertificateResponse(custom).RevocationReason; got != custom.RevocationReason {
		t.Fatalf("non-ACME reason changed to %q", got)
	}
}
