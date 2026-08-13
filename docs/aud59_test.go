// SPDX-License-Identifier: MPL-2.0

package docs_test

import (
	"os"
	"strings"
	"testing"
)

func TestAUD59ProviderInvoiceEvidenceDocumentationMatchesServedWorkflow(t *testing.T) {
	limitations, err := os.ReadFile("limitations.md")
	if err != nil {
		t.Fatal(err)
	}
	editions, err := os.ReadFile("editions.md")
	if err != nil {
		t.Fatal(err)
	}
	combined := string(limitations) + "\n" + string(editions)
	for _, required := range []string{
		"/provider/v1/tenants/{id}/usage-evidence",
		"/provider/v1/evidence/verification-keys",
		"read delegation",
		"signed JSON",
		"finance CSV",
		"Signature verified",
	} {
		if !strings.Contains(combined, required) {
			t.Errorf("AUD-59 docs omit %q", required)
		}
	}
	if strings.Contains(string(limitations), "cross-customer evidence pulls still require the provider delegation\n  route that does not exist") {
		t.Fatal("limitations still say the now-served Provider evidence route does not exist")
	}
}
