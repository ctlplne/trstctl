// SPDX-License-Identifier: BUSL-1.1

package docs_test

import (
	"os"
	"strings"
	"testing"
)

func TestAUD60ProviderCustomerHealthDocumentationMatchesServedWorkflow(t *testing.T) {
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
		"/provider/v1/tenants/{id}/health",
		"active-certificate",
		"read delegation",
		"unknown",
		"Invoice evidence",
	} {
		if !strings.Contains(combined, required) {
			t.Errorf("AUD-60 docs omit %q", required)
		}
	}
}
