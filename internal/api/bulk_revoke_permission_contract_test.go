// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"strings"
	"testing"
)

// N7-L1: bulk revocation needs identities:write, and selecting exact
// certificates (certificate_ids) also needs certs:issue; the handler refuses
// that request with 403 otherwise. The served contract named only
// identities:write, so a client given just that permission could not tell
// why its exact-certificate revocation was refused.
func TestBulkRevokeContractNamesCertsIssueForExactCertificatesN7L1(t *testing.T) {
	doc := fetchSpec(t)
	op := asMap(asMap(asMap(doc["paths"])["/api/v1/certificates/bulk-revoke"])["post"])
	if op["x-trstctl-permission"] != "identities:write" {
		t.Fatalf("bulk revoke permission = %v", op["x-trstctl-permission"])
	}
	also, _ := op["x-trstctl-also-requires"].([]any)
	for _, raw := range also {
		entry := asMap(raw)
		when, _ := entry["when"].(string)
		if entry["permission"] == "certs:issue" && strings.Contains(when, "certificate_ids") {
			return
		}
	}
	t.Fatalf("bulk revoke does not say exact certificates also need certs:issue: %v", op["x-trstctl-also-requires"])
}
