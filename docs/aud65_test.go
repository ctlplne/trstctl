// SPDX-License-Identifier: MPL-2.0

package docs_test

import (
	"os"
	"strings"
	"testing"
)

func TestAUD65DocsNameCanonicalReadinessWorkflowAndEvidence(t *testing.T) {
	files := []string{
		"features/observability-and-risk.md", "features/lifecycle-and-pqc.md",
		"limitations.md", "web-console.md", "compliance.md", "cli.md",
	}
	joined := ""
	for _, name := range files {
		raw, err := os.ReadFile(name) // #nosec G304 -- name comes from the fixed documentation manifest in this test (CWE-22).
		if err != nil {
			t.Fatal(err)
		}
		joined += string(raw)
	}
	for _, required := range []string{
		"/api/v1/graph/crypto-readiness/actions", "/api/v1/graph/crypto-readiness/export",
		"dataset_digest", "CSV", "NDJSON", "offline verification", "coverage",
		"stale", "409", "signed_export.manifest.crypto_readiness", "evidence-pack.v5",
		"graph crypto-readiness actions create", "graph crypto-readiness export",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("AUD-65 documentation omits %q", required)
		}
	}
}
